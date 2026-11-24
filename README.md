# manifest-gate

Pre-merge policy gate for Kubernetes manifests in a GitOps repository.

Admission rules in the cluster reject a bad object only **after** the change is merged and synced. The GitOps controller then gets stuck, and you have to work out which change caused it. `manifest-gate` applies the same conditions to the manifests in the pull request, **before** merge, and exits non-zero on a violation.

## Rules

| ID | Rule | Why |
|---|---|---|
| R1 | Images are pinned by digest (`@sha256:`) | Tags move. A digest is what admission policies and signature checks verify |
| R2 | No local-only images (node caches, ad-hoc registries) | They disappear on garbage collection or a node change, and usually have no signature |
| R3 | Workloads in selected namespaces have a `readinessProbe` and a memory limit | Mirrors a common admission rule. Without it, rollouts route traffic to pods that aren't ready, and a leak can take the node down |
| R4 | Every namespace has a default-deny ingress `NetworkPolicy` | Makes allow-lists explicit |
| R5 | Secrets with data live only in encrypted files (`*.sops.yaml`) | Stops plaintext secrets at review time |
| R6 | Namespaces and PVCs under the app paths opt out of pruning | With pruning on, deleting a file must not delete the data |

Two behaviours that came from running this in production:

- **Dormant violations** (workloads scaled to `0`) are reported as warnings. They are harmless today, but the pods will be rejected the moment someone scales them back up. Without this, those failures only show up during an incident.
- **Exceptions must justify themselves.** Each one needs a `reason` and a `review_by` date. An expired exception, or one that no longer matches anything, fails the gate. Exceptions can't silently pile up.

## Usage

```bash
pip install git+https://github.com/Atsu1979/manifest-gate
manifest-gate path/to/repo                      # uses path/to/repo/manifest-gate.yaml if present
manifest-gate path/to/repo -c manifest-gate.yaml
```

See [`examples/manifest-gate.yaml`](examples/manifest-gate.yaml) for every option. In CI, run it on every pull request and require it before merge. If branch protection is not available, have the GitOps controller follow a release branch that only CI can advance.

## Development

```bash
pip install -e ".[test]"
python -m pytest -q
```

The gate itself is tested: deliberately bad changes must fail, and good ones must pass.

---

### 日本語

GitOps リポジトリの Kubernetes マニフェストに、クラスタの受け入れ規則と同じ条件を**マージの前**に当てる、小さな関門です。違反があれば終了コード 1 を返します。台数 0 で眠っている違反は警告として出します。例外には理由と見直し日を必須にし、期限切れや当たらなくなった例外は不合格にします。

MIT License.
