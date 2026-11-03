"""Measure how long the gate takes on a synthetic GitOps repository.

    python bench/bench.py --namespaces 500 --repeat 5
    python bench/bench.py --namespaces 500 --repeat 5 --loader python   # pure-Python YAML, for comparison

Each namespace gets: Namespace + default-deny NetworkPolicy (1 file), a Deployment,
a CronJob and a PVC (1 file), and an encrypted Secret (1 file) = 3 files / 6 documents.
Every 10th namespace gets one violation, so the result also shows the gate finds them.
Prints the median wall time of `check()` over --repeat runs; nothing is hard-coded.
"""
import argparse
import os
import platform
import statistics
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import yaml  # noqa: E402

import manifest_gate.check as mg  # noqa: E402
from manifest_gate.check import Config, check  # noqa: E402

DIGEST = "registry.example.com/app@sha256:" + "a" * 64
GUARD = "annotations: {kustomize.toolkit.fluxcd.io/prune: disabled}"


def build(root: str, n: int) -> int:
    planted = 0
    for i in range(n):
        name = f"ns{i:04d}"
        d = os.path.join(root, "apps", name)
        os.makedirs(d)
        image = DIGEST
        if i % 10 == 0:
            image, planted = "nginx:latest", planted + 1
        with open(os.path.join(d, "00-namespace.yaml"), "w") as f:
            f.write(f"apiVersion: v1\nkind: Namespace\nmetadata: {{name: {name}, {GUARD}}}\n---\n"
                    f"apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\n"
                    f"metadata: {{name: deny, namespace: {name}}}\nspec: {{podSelector: {{}}, policyTypes: [Ingress]}}\n")
        with open(os.path.join(d, "10-app.yaml"), "w") as f:
            f.write(f"""apiVersion: apps/v1
kind: Deployment
metadata: {{name: app, namespace: {name}}}
spec:
  replicas: 2
  selector: {{matchLabels: {{app: app}}}}
  template:
    metadata: {{labels: {{app: app}}}}
    spec:
      containers:
      - name: app
        image: {image}
        readinessProbe: {{httpGet: {{path: /, port: 80}}}}
        resources: {{limits: {{memory: 128Mi}}}}
---
apiVersion: batch/v1
kind: CronJob
metadata: {{name: job, namespace: {name}}}
spec:
  schedule: "0 3 * * *"
  jobTemplate:
    spec:
      template:
        metadata: {{labels: {{app: job}}}}
        spec:
          containers:
          - name: job
            image: {DIGEST}
            readinessProbe: {{exec: {{command: ["true"]}}}}
            resources: {{limits: {{memory: 64Mi}}}}
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata: {{name: data, namespace: {name}, {GUARD}}}
spec: {{accessModes: [ReadWriteOnce], resources: {{requests: {{storage: 1Gi}}}}}}
""")
        with open(os.path.join(d, "20-secret.sops.yaml"), "w") as f:
            f.write(f"apiVersion: v1\nkind: Secret\nmetadata: {{name: s, namespace: {name}}}\n"
                    f"data: {{K: 'ENC[AES256_GCM,data:AAAA,type:str]'}}\nsops: {{version: 3.9.0}}\n")
    return planted


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--namespaces", type=int, default=500)
    ap.add_argument("--repeat", type=int, default=5)
    ap.add_argument("--loader", choices=["auto", "python"], default="auto",
                    help="python = force the pure-Python yaml.SafeLoader, to compare with libyaml")
    a = ap.parse_args()
    if a.loader == "python":
        mg.LOADER = yaml.SafeLoader
    with tempfile.TemporaryDirectory() as root:
        planted = build(root, a.namespaces)
        cfg = Config(health_namespaces={f"ns{i:04d}" for i in range(a.namespaces)})
        times, stats, errs = [], {}, []
        for _ in range(a.repeat):
            stats = {}
            t0 = time.perf_counter()
            errs, _ = check(root, cfg, stats=stats)
            times.append(time.perf_counter() - t0)
    print(f"python={platform.python_version()} cpu_count={os.cpu_count()} loader={mg.LOADER.__name__}")
    print(f"namespaces={a.namespaces} files={stats['files']} documents={stats['documents']}")
    print(f"planted_violations={planted} reported_errors={len(errs)}")
    med = statistics.median(times)
    print(f"median_seconds={med:.3f} min_seconds={min(times):.3f} max_seconds={max(times):.3f} runs={a.repeat}")
    print(f"documents_per_second={stats['documents'] / med:.0f}")


if __name__ == "__main__":
    main()
