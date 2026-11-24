"""manifest-gate: a small pre-merge policy gate for Kubernetes manifests in a GitOps repository.

Admission rules in the cluster reject a bad object only *after* it has been merged and synced,
which leaves the GitOps controller stuck and the culprit change hard to find. This tool applies
the same conditions to the manifests in the pull request, before merge.
"""
__version__ = "0.1.0"
