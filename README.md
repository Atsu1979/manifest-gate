# manifest-gate

[![ci](https://github.com/Atsu1979/manifest-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/Atsu1979/manifest-gate/actions/workflows/ci.yml)

GitOps リポジトリの Kubernetes マニフェストを、クラスタの受け入れ規則（admission）と同じ条件で**マージ前に**検査する小さな関門（CLI）です。違反があれば終了コード 1 を返し、プルリクエストのマージを止めます。

## 目的

クラスタ側の admission ルールは、変更がマージされて同期された**後**にしか不正なオブジェクトを拒否しません。すると GitOps コントローラ（Flux など）が同期途中で止まり、どの変更が原因かを後から探すことになります。

`manifest-gate` は同じ条件をプルリクエストの段階で当てます。

- 失敗を**レビュー時**に、**どのファイルのどのコンテナか**まで特定して出す
- 依存は PyYAML だけ。クラスタへの接続も認証情報も要らない（CI でそのまま動く）
- 「今は無害だが将来壊れる」違反や、放置された例外も見逃さない

## 検査ルール

| ID | ルール | 理由 |
|---|---|---|
| R1 | イメージをダイジェスト（`@sha256:`）で固定する | タグは動く。署名検証や admission が確認するのはダイジェスト |
| R2 | ノードのキャッシュや臨時レジストリにしかないイメージを使わない | GC やノード入れ替えで消え、署名もないことが多い |
| R3 | 指定した namespace のワークロードに `readinessProbe` とメモリ上限がある | 準備前の Pod に流量が流れる・メモリリークでノードが落ちるのを防ぐ |
| R4 | すべての namespace に既定拒否（default-deny）の ingress `NetworkPolicy` がある | 許可を明示的なホワイトリストにする |
| R5 | データを持つ Secret は暗号化ファイル（`*.sops.yaml`）にだけ置き、実際に SOPS で暗号化されている | 平文の秘密情報をレビュー時点で止める |
| R6 | アプリ配下の Namespace と PVC は GitOps の prune 対象から外す | ファイル削除でデータまで消えるのを防ぐ |

運用から生まれた2つの振る舞い:

- **休眠中の違反**（`replicas: 0` のワークロード）は警告として出します。今は無害でも、誰かがスケールした瞬間に Pod が拒否されるためです。
- **例外は理由と期限が必須**です。各例外に `reason` と `review_by`（`YYYY-MM-DD`）が要り、期限切れの例外・もう何にも当たらない例外は不合格になります。例外が黙って積み上がることはありません。

## 使い方

```bash
pip install git+https://github.com/Atsu1979/manifest-gate
```

```bash
manifest-gate path/to/repo
```

```bash
manifest-gate path/to/repo -c manifest-gate.yaml
```

`-c` を省略すると `path/to/repo/manifest-gate.yaml` があれば読みます。設定項目はすべて [`examples/manifest-gate.yaml`](examples/manifest-gate.yaml) にあります。

### 終了コード

| コード | 意味 |
|---|---|
| 0 | 合格（警告のみの場合を含む） |
| 1 | ポリシー違反あり（`FAIL` 行を出力） |
| 2 | 関門を実行できない（ルートが無い、`-c` のファイルが無い、設定キーの誤字、マニフェストが1件も無い など） |

「設定の誤字や指定ミスで、ルールが黙って無効になったまま合格する」ことを防ぐため、こうした入力は 1 でも 0 でもなく 2 で止めます。

### 出力例

同梱の例（`examples/`）を実際に実行した出力です。

```text
$ manifest-gate examples/repo -c examples/manifest-gate.yaml
WARN R4 namespace policy-engine: no default-deny ingress NetworkPolicy (known exception: admission webhooks need ingress from the API server; add a scoped allow rule first; review by 2099-12-31)
checked: files=3 documents=4 errors=0 warnings=1
（終了コード 0）

$ manifest-gate examples/bad-repo
FAIL R6 apps/shop/00-namespace.yaml: Namespace/shop is not protected from pruning (kustomize.toolkit.fluxcd.io/prune: disabled)
FAIL R1 apps/shop/10-app.yaml: Deployment/shop (ns=shop): container shop image is not pinned by digest: nginx:1.27
FAIL R2 apps/shop/10-app.yaml: Deployment/shop (ns=shop): container migrate uses a local-only image: localhost:5000/shop-migrate@sha256:1111111111111111111111111111111111111111111111111111111111111111
FAIL R3 apps/shop/10-app.yaml: Deployment/shop (ns=shop): container shop lacks a readinessProbe or a memory limit
FAIL R5 apps/shop/10-app.yaml: Secret/shop-db holds data outside an encrypted file
FAIL R6 apps/shop/10-app.yaml: PersistentVolumeClaim/shop-data is not protected from pruning (kustomize.toolkit.fluxcd.io/prune: disabled)
FAIL R4 namespace shop: no default-deny ingress NetworkPolicy
checked: files=2 documents=4 errors=7 warnings=0
（終了コード 1）
```

`examples/bad-repo` はわざと壊したリポジトリで、R1〜R6 をすべて踏みます（Secret の値はダミーです）。

### CI への組み込み（GitHub Actions の例）

```yaml
- uses: actions/setup-python@v5
  with: {python-version: "3.12"}
- run: pip install "git+https://github.com/Atsu1979/manifest-gate@<コミットSHA>"
- run: manifest-gate . -c manifest-gate.yaml
```

すべてのプルリクエストで実行し、マージ前の必須チェックにしてください。供給網の安全のため、取り込むバージョンはコミット SHA で固定することを勧めます。ブランチ保護が使えない場合は、CI だけが進められるリリース用ブランチを GitOps コントローラに追わせます。

## 実測結果

数値はすべて、このリポジトリのコードを下記環境で実行して得たものです。

**環境:** Intel(R) Xeon(R) Processor @ 2.10GHz（4コア）、Linux、Python 3.13.18、PyYAML 6.0.3

### テスト

| 項目 | 結果 | 実行コマンド |
|---|---|---|
| テスト件数 | 49 件すべて成功 | `python -m pytest -q` |
| 行カバレッジ | 97%（`check.py` は 99%） | `python -m pytest --cov=manifest_gate` |
| 対応 Python | 3.10 / 3.11 / 3.12 / 3.13 で全件成功 | CI のマトリクス（ローカルでも各版で実行済み） |
| Lint | 指摘 0 件 | `ruff check .` |

### 処理速度

`bench/bench.py` で合成した GitOps リポジトリ（1 namespace あたり 3 ファイル / 6 ドキュメント、10 namespace に 1 件の違反を混入）を検査し、5 回の中央値を取りました。

| namespace 数 | ファイル | ドキュメント | 混入した違反 → 検出 | 改善前（純 Python の YAML 読み込み） | 改善後（libyaml の C 読み込み） |
|---:|---:|---:|---:|---:|---:|
| 100 | 300 | 600 | 10 → 10 | 0.449 秒 | 0.069 秒 |
| 500 | 1,500 | 3,000 | 50 → 50 | 2.298 秒 | 0.335 秒 |
| 2,000 | 6,000 | 12,000 | 200 → 200 | 9.769 秒 | 1.469 秒 |

YAML の読み込みを `CSafeLoader`（libyaml）に切り替え、同じ入力で約 6.5〜6.9 倍速くなりました。混入した違反は全規模で取りこぼしなく検出しています。libyaml が無い環境では自動的に純 Python 版にフォールバックし、両者で出力が一致することをテストで確認しています。

再現方法:

```bash
python bench/bench.py --namespaces 500 --repeat 5
```

```bash
python bench/bench.py --namespaces 500 --repeat 5 --loader python
```

## 開発

```bash
pip install -e ".[test]"
```

```bash
ruff check . && python -m pytest -q --cov=manifest_gate
```

関門そのものをテストしています。わざと壊した変更は落ち、正しい変更は通ることを確認します（`tests/`）。CI（`.github/workflows/ci.yml`）は Python 3.10〜3.13 で lint・テスト（カバレッジ 90% 未満で失敗）・良い例の合格・悪い例の不合格（終了コード 1）・ベンチマークを実行します。

## 構成

```text
manifest_gate/check.py   ルール・設定読み込み・CLI
tests/                   単体テスト・回帰テスト・例を使った受け入れテスト
examples/repo            合格する例
examples/bad-repo        R1〜R6 をすべて踏む例
bench/bench.py           処理速度の計測
```

---

### English summary

Pre-merge policy gate for Kubernetes manifests in a GitOps repository. It applies admission-style rules (R1–R6 above) to the manifests in a pull request and exits 1 on a violation, 2 if it cannot run (missing root or config, unknown config key, no manifests found). Dormant violations (`replicas: 0`) are warnings; exceptions need a `reason` and a `review_by` date and fail once expired or stale.

MIT License.
