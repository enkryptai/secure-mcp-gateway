# Kubernetes Deployment Runbook — Secure MCP Gateway

**Audience**: DevOps / whoever is on release duty.
**Purpose**: Document the manual dev deploy exactly as performed today, so it can
be automated, and lay out what must change to run the same thing in prod.
**Last verified against the live clusters**: 2026-08-17 (gateway `v2.2.1-1`).

---

## 1. Scope

| Aspect | Today |
| --- | --- |
| **What's automated today** | Nothing. PyPI publishing is the only CI ([.github/workflows/publish.yml](../../.github/workflows/publish.yml)); it does **not** build or push the Docker image. |
| **What's manual today** | Docker build → Docker Hub push → edit image tag in a gitignored manifest → `kubectl apply`. |
| **Where dev runs** | EKS `eks-dev`, account `188451452903`, region `us-east-1`, namespace **`dev`**. |
| **Where prod would run** | EKS `eks-prod`, same account/region, namespace **`production`**. **Not deployed yet** — see [§7](#7-prod-deployment-not-yet-deployed). |

---

## 2. Live dev topology (verified)

```text
Internet
  │  https://mcp.dev.enkryptai.com
  ▼
Ingress  mcp-server            (ns dev, class "nginx", TLS secret mcp-tls,
  │                            issuer letsencrypt-prod, path / Prefix)
  ▼
Service  secure-mcp-gateway-service   ClusterIP :80 → targetPort 8000
  ▼
Deployment secure-mcp-gateway   replicas: 1
  ├── initContainer  config-downloader (amazon/aws-cli:latest)
  │     └── aws s3 cp s3://mcpserver-enkryptai/enkrypt_mcp_config.json
  │            → emptyDir volume "shared-config" → /app/.enkrypt/docker/
  └── container      secure-mcp-gateway (enkryptai/secure-mcp-gateway:v2.2.1-1)
        └── python src/secure_mcp_gateway/gateway.py  → :8000
```

### Resource ownership — read this before you apply

| Resource | In [secure-mcp-gateway-manifest.yaml](../secure-mcp-gateway-manifest.yaml)? | Notes |
| --- | --- | --- |
| `Secret/s3-credentials` | ✅ yes | Re-applied on every deploy. Contains **static long-lived AWS keys**, base64 in the file. See [§6.2](#62-static-aws-keys-in-a-gitignored-file). |
| `Deployment/secure-mcp-gateway` | ✅ yes | The only thing a version bump actually changes. |
| `Service/secure-mcp-gateway-service` | ✅ yes | ClusterIP, port 80 → 8000. |
| `Ingress/mcp-server` | ❌ **no** | Created 2025-07-18, lives only in the cluster. A version bump never touches it. |
| OTel env vars on the container | ❌ **no** | Cluster-only drift. See [§6.1](#61-otel-env-vars-exist-only-in-the-cluster). |
| `enkrypt_mcp_config.json` | ❌ no | Lives in S3, pulled at pod start. See [§5](#5-config-change-with-no-image-rebuild). |

The manifest has **no `namespace:` in any `metadata:` block** — the `-n dev` on
the `kubectl apply` is what puts it in the right place. Omit it and you deploy
into `default`.

---

## 3. Prerequisites (one-time per operator)

```bash
# 1. Docker Hub push access to enkryptai/secure-mcp-gateway
docker login

# 2. kubeconfig entries for both clusters
aws eks update-kubeconfig --region us-east-1 --name eks-dev
aws eks update-kubeconfig --region us-east-1 --name eks-prod

# 3. The real manifest (gitignored — it holds credentials)
#    Not in git. Copy from another operator, or start from the tracked template:
cp docs/secure-mcp-gateway-manifest-example.yaml docs/secure-mcp-gateway-manifest.yaml
#    then fill in the base64 values in the s3-credentials Secret.
```

`docs/secure-mcp-gateway-manifest.yaml` is ignored via [.gitignore:77](../../.gitignore).
**Keep it that way** — it contains plaintext-recoverable AWS credentials.

---

## 4. Dev deploy runbook

### 4.1 Pick the tag

Scheme is `v<package-version>-<build>`, e.g. `v2.2.1-1`.

- `<package-version>` comes from [src/secure_mcp_gateway/version.py](../../src/secure_mcp_gateway/version.py) (currently `2.2.1`).
- `<build>` starts at `1` and increments for each rebuild of the *same* package
  version. **Never reuse a tag** — see [§6.3](#63-never-reuse-a-tag).

```bash
VERSION=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' src/secure_mcp_gateway/version.py)   # → 2.2.1
BUILD=1
TAG="v${VERSION}-${BUILD}"
IMAGE="enkryptai/secure-mcp-gateway:${TAG}"
```

### 4.2 Build and push

```bash
# From the repo root (the Dockerfile COPYs src/, requirements.txt, pyproject.toml)
docker build --platform linux/amd64 -t "$IMAGE" -t enkryptai/secure-mcp-gateway:latest .
docker push "$IMAGE"
docker push enkryptai/secure-mcp-gateway:latest
```

Two notes vs. the commands run by hand today:

- **One build, two tags.** `docker build -t A . && docker build -t B .` runs the
  builder twice; `-t A -t B` produces one image with both tags and is
  unambiguously the same bits under each name.
- **`--platform linux/amd64`.** All 7 dev nodes and all 15 prod nodes are
  `amd64`. Harmless on an x86 host; mandatory if anyone ever builds on an Apple
  Silicon Mac, where the default build would produce an arm64 image that
  `CrashLoopBackOff`s with `exec format error`.

`latest` is a **dev-only convenience**. It is never referenced by a manifest and
must not be used by prod ([§6.3](#63-never-reuse-a-tag)).

### 4.3 Point the manifest at the new tag

Edit [docs/secure-mcp-gateway-manifest.yaml](../secure-mcp-gateway-manifest.yaml),
the `containers:` entry (~line 101):

```yaml
      containers:
      - name: secure-mcp-gateway
        image: enkryptai/secure-mcp-gateway:v2.2.1-1   # ← bump this
```

Leave `imagePullPolicy` commented out. With an immutable tag the default
(`IfNotPresent`) is correct and avoids a registry round-trip per pod start.

### 4.4 Switch context and apply

```bash
kubectx arn:aws:eks:us-east-1:188451452903:cluster/eks-dev
# ✔ Switched to context "arn:aws:eks:us-east-1:188451452903:cluster/eks-dev".

kubectl config current-context      # confirm before every apply

kubectl apply -f docs/secure-mcp-gateway-manifest.yaml -n dev
```

Recommended: dry-run the diff first.

```bash
kubectl diff -f docs/secure-mcp-gateway-manifest.yaml -n dev
```

The only lines in that diff should be the image tag. If you see the OTel env
vars being removed, **stop** and read [§6.1](#61-otel-env-vars-exist-only-in-the-cluster).

### 4.5 Verify

```bash
kubectl rollout status deploy/secure-mcp-gateway -n dev --timeout=300s

# init container pulled the config?
kubectl logs deploy/secure-mcp-gateway -n dev -c config-downloader | head -20

# gateway came up?
kubectl logs deploy/secure-mcp-gateway -n dev -c secure-mcp-gateway --tail=50

# running image is what you just pushed?
kubectl get deploy secure-mcp-gateway -n dev \
  -o jsonpath='{.spec.template.spec.containers[0].image}{"\n"}'
```

External smoke test — these are the **expected** responses for a healthy gateway
(there is no unauthenticated health endpoint on port 8000):

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://mcp.dev.enkryptai.com/
# → 200   (OAuth landing page — proves ingress + TLS + pod)

curl -s -o /dev/null -w '%{http_code}\n' https://mcp.dev.enkryptai.com/mcp/
# → 406   (MCP transport rejects a plain GET — proves FastMCP is mounted)

curl -s https://mcp.dev.enkryptai.com/api/v1/cache/last-reload
# → 401 {"status":"error","error":"apikey header required","reason":"missing_apikey"}
#        (proves the app, not the ingress, is answering)
```

A `502`/`503` from any of these means the pod is not ready; a connection
timeout means the ingress or LB is the problem, not the deploy.

### 4.6 Rollback

```bash
kubectl rollout undo deploy/secure-mcp-gateway -n dev
kubectl rollout status deploy/secure-mcp-gateway -n dev
```

Then revert the image tag in the manifest so the file matches the cluster.
Because every build gets a fresh immutable tag, the previous ReplicaSet's image
is still pullable — rollback is always available.

---

## 5. Config change with no image rebuild

The gateway config is **not** baked into the image. The init container copies
`s3://mcpserver-enkryptai/enkrypt_mcp_config.json` into an `emptyDir` at
`/app/.enkrypt/docker/` on every pod start.

```bash
aws s3 cp enkrypt_mcp_config.json s3://mcpserver-enkryptai/enkrypt_mcp_config.json
kubectl rollout restart deploy/secure-mcp-gateway -n dev
kubectl rollout status  deploy/secure-mcp-gateway -n dev
```

**The `rollout restart` is required.** The in-process config watcher and the
`POST /api/v1/cache/flush-gateway-config` endpoint (see
[CLAUDE.md § Zero-Restart Hot-Reload](../../CLAUDE.md)) both re-read the *local*
file — and that local file is an `emptyDir` copy that only changes when the init
container runs again. Updating S3 alone changes nothing in a running pod.

Same applies after editing the `s3-credentials` Secret: `kubectl apply` updates
the Secret but does not restart pods that consumed it via `env.valueFrom`.

---

## 6. Known drift and gotchas

### 6.1 OTel env vars exist only in the cluster

The live Deployment carries 10 environment variables that are **not** in the
manifest and not in its `last-applied-configuration`:

```text
SKIP_DEPENDENCY_INSTALL=true
HOST_IP=<fieldRef: status.hostIP>
OTEL_EXPORTER_OTLP_ENDPOINT=http://$(HOST_IP):4317
OTEL_EXPORTER_OTLP_PROTOCOL=grpc
OTEL_SERVICE_NAME=secure-mcp-gateway
OTEL_RESOURCE_ATTRIBUTES=deployment.environment=dev,k8s.namespace.name=dev
OTEL_TRACES_EXPORTER=otlp
OTEL_METRICS_EXPORTER=otlp
OTEL_LOGS_EXPORTER=otlp
OTEL_PYTHON_LOG_CORRELATION=true
```

They point at the `otel-collector-opentelemetry-collector-agent` DaemonSet in
namespace `opentelemetry` via the node's host IP (Data Prepper → OpenSearch is
also in that namespace).

- **Today's `kubectl apply` preserves them.** Client-side apply does a three-way
  merge; fields present in the live object but absent from *both* the
  last-applied annotation and the incoming file are left alone.
- **These lose telemetry silently**: `kubectl delete` + `apply`, `kubectl replace`,
  `kubectl apply --server-side --force-conflicts`, or a first deploy into a new
  cluster (prod) from this manifest.

**Action for DevOps**: fold this `env:` block into the manifest so it is
declarative, using `deployment.environment=prod,k8s.namespace.name=production`
for the prod variant. Until then, treat it as a fragile out-of-band patch.

### 6.2 Static AWS keys in a gitignored file

`Secret/s3-credentials` holds long-lived `AWS_ACCESS_KEY_ID` /
`AWS_SECRET_ACCESS_KEY` values, base64-encoded (not encrypted) in a file on
operator laptops. Every other app in namespace `dev` — `guardrails`, `litellm`,
`frontend`, `gateway-kong`, … — instead uses **ExternalSecrets** against the
`aws-secret-store` SecretStore.

**Action for DevOps, required before prod:** replace the hand-maintained Secret
with either

- an `ExternalSecret` following the pattern in
  `enkryptai-apiaas/code/infra/kubernetes/apps/guardrails/dev/external-secret.yaml`, or
- **IRSA** — a ServiceAccount annotated with an IAM role granting
  `s3:GetObject` on the one config key, which removes the static keys entirely
  (the `amazon/aws-cli` init container picks up the web-identity credentials with
  no code change).

Whichever is chosen, the manifest checked into git should stop carrying
credentials at all, and `docs/secure-mcp-gateway-manifest.yaml` can come out of
`.gitignore`.

### 6.3 Never reuse a tag

`imagePullPolicy` is unset, so it defaults to `IfNotPresent` for a pinned tag.
If you rebuild and re-push `v2.2.1-1`, nodes that already cached that tag keep
serving the **old** bits, and you get a half-upgraded fleet that is very hard to
diagnose. Always increment the build number.

This is also exactly why `latest` must never appear in a manifest: `latest` +
`IfNotPresent` pins whatever each node happened to pull first, and `latest` +
`Always` makes rollbacks impossible because there is no earlier tag to go back to.

### 6.4 `replicas: 1` is load-bearing for OAuth

Pending OAuth flows are held **in process**, keyed by `state` with a 600 s TTL
(`_pending_flows` in
[gateway_oauth_routes.py](../../src/secure_mcp_gateway/gateway_oauth_routes.py)).
The browser's `/oauth2callback` request must land on the pod that started the
flow. Scaling past one replica without sticky sessions produces intermittent
*"Invalid or Expired State"* errors. See
[CENTRALIZED_OAUTH_CALLBACK.md](../CENTRALIZED_OAUTH_CALLBACK.md) for the full
remote-callback checklist.

### 6.5 The dev `nginx` IngressClass is not ingress-nginx

In `eks-dev`, **both** the `nginx` and `traefik` IngressClasses are backed by
controller `traefik.io/ingress-controller`. So the
`nginx.ingress.kubernetes.io/proxy-buffer-size: 128k` annotation on
`Ingress/mcp-server` is inert in dev. In `eks-prod` the `nginx` class is real
`k8s.io/ingress-nginx`, so that annotation *will* take effect there — worth
knowing when comparing behaviour between the two environments.

### 6.6 The REST API port is not exposed

The gateway container also serves the management REST API on **8001**, but the
Deployment declares only `containerPort: 8000` and the Service maps `80 → 8000`.
The endpoints reachable through the ingress are the ones FastMCP mounts on 8000
(`/mcp/`, `/oauth2callback`, `/api/v1/cache/*`, `/mcp-playground/*`). Use
`kubectl port-forward` if you need the 8001 API against a live pod.

---

## 7. Prod deployment (not yet deployed)

Verified on 2026-08-17: `eks-prod` has **no** `secure-mcp-gateway` Deployment,
Service, or Ingress in any namespace. Only `mcp-scanner` (namespace
`production`) is there. The following is a from-zero checklist, not a runbook
that has been executed.

### 7.1 What prod already provides

| Dependency | Status in `eks-prod` |
| --- | --- |
| Namespace `production` | ✅ exists |
| IngressClass `nginx` (real ingress-nginx) | ✅ exists |
| IngressClass `traefik` | ✅ exists — used by every current prod app (`api.enkryptai.com`, `mcpscanner.enkryptai.com`, …) |
| ClusterIssuer `letsencrypt-prod` | ✅ exists (TLS certs work the same way) |
| OTel agent DaemonSet on the node host IP | ✅ `otel-collector-opentelemetry-collector-agent`, ns `opentelemetry`, 15 nodes |
| ExternalSecrets operator | ✅ ns `external-secrets` exists |
| Node architecture | ✅ all 15 nodes `amd64` |

### 7.2 What must be decided or created

1. **Hostname + Ingress.** Pick the public name (`mcp.enkryptai.com`, matching
   the `mcpscanner.enkryptai.com` convention), create the DNS record, and author
   an `Ingress` — it does **not** exist and is **not** in the manifest. Follow
   the prod convention (`ingressClassName: traefik`) unless there's a reason to
   use real nginx. Must route `/` (not just `/mcp/`) so `/oauth2callback` works.
2. **S3 config key.** Same bucket, per-environment prefix — `prod/enkrypt_mcp_config.json`
   alongside `dev/enkrypt_mcp_config.json`. This requires editing the init
   container's `aws s3 cp` line to take the key from an env var rather than
   hardcoding `enkrypt_mcp_config.json`, e.g.
   `aws s3 cp s3://${S3_BUCKET_NAME}/${S3_CONFIG_KEY} …`. **Do this before the
   first prod deploy** — otherwise prod boots on the dev config.
3. **Credentials.** Do not copy the dev static-key Secret. Use ExternalSecrets or
   IRSA per [§6.2](#62-static-aws-keys-in-a-gitignored-file), scoped to the prod key only.
4. **OTel env block.** Add it to the manifest with
   `OTEL_RESOURCE_ATTRIBUTES=deployment.environment=prod,k8s.namespace.name=production`.
   Skipping this means a prod gateway with zero telemetry
   ([§6.1](#61-otel-env-vars-exist-only-in-the-cluster)).
5. **`ENKRYPT_GATEWAY_BASE_URL`.** Set to the public prod HTTPS URL, and register
   `<base>/oauth2callback` with every IdP in use (Google Cloud Console, etc.).
   Without it the gateway advertises a pod-IP redirect and OAuth fails.
6. **Resource requests/limits.** The Deployment currently declares none, so pods
   land in the `BestEffort` QoS class and are first to be evicted under node
   pressure. Set requests/limits before prod.
7. **Probes.** No `readinessProbe`/`livenessProbe` today, so the Service starts
   sending traffic the moment the container process starts — before FastMCP is
   listening. Add at minimum a readiness probe on `:8000` (a TCP socket probe is
   the simplest correct choice; `GET /` returns 200 once the app is up).
8. **Replica strategy.** Keep `replicas: 1` until OAuth pending-flow state is
   shared, or enable sticky sessions ([§6.4](#64-replicas-1-is-load-bearing-for-oauth)).

### 7.3 Prod deploy sequence (once the above exists)

```bash
docker build --platform linux/amd64 -t "enkryptai/secure-mcp-gateway:${TAG}" .
docker push "enkryptai/secure-mcp-gateway:${TAG}"        # pinned tag only, no `latest`

kubectx arn:aws:eks:us-east-1:188451452903:cluster/eks-prod
kubectl config current-context                            # confirm — this is prod

kubectl diff  -f <prod-manifest>.yaml -n production       # review before applying
kubectl apply -f <prod-manifest>.yaml -n production
kubectl rollout status deploy/secure-mcp-gateway -n production --timeout=300s
```

Promote the **exact tag** already verified in dev. Do not rebuild between
environments — a rebuild from the same source can still differ (base-image
updates, unpinned transitive deps), which defeats the point of testing in dev.

---

## 8. Notes for automating this

The manual flow maps onto a pipeline cleanly. Suggested shape:

1. **Trigger** — tag push `v*` (or manual dispatch with a build number).
2. **Build & push** — `docker/build-push-action` with `platforms: linux/amd64`,
   tags `v${VERSION}-${BUILD}` (+ `latest` on the dev path only), Docker Hub
   creds from repo secrets. Reuse the existing `test` job in
   [publish.yml](../../.github/workflows/publish.yml) as a gate.
3. **Deploy dev** — assume an IAM role via OIDC, `aws eks update-kubeconfig
   --name eks-dev`, render the image tag into the manifest (`kustomize edit set
   image`, `yq`, or a Helm value — anything that removes the hand-edit), then
   `kubectl apply -n dev` and `kubectl rollout status`.
4. **Promote to prod** — a manually-approved job that reuses the *same* tag
   against `eks-prod` / `production`.

Three things to fix as part of automating, because they block a clean pipeline:

- **The manifest is gitignored.** A pipeline can't apply a file that isn't in the
  repo. Removing the credentials from it (ExternalSecrets/IRSA,
  [§6.2](#62-static-aws-keys-in-a-gitignored-file)) is what unblocks this.
- **The OTel env is out-of-band** ([§6.1](#61-otel-env-vars-exist-only-in-the-cluster)).
  Any pipeline that recreates the Deployment will silently drop telemetry.
- **Dev and prod need to differ by overlay, not by hand-editing one file.** A
  Kustomize base + `dev`/`production` overlays matches what the apiaas repo
  already does for `guardrails` and `litellm`
  (`kustomization.yaml` + `external-secret.yaml` per environment).

---

## 9. Command quick reference

```bash
# Build + push (dev)
docker build --platform linux/amd64 \
  -t enkryptai/secure-mcp-gateway:v2.2.1-1 \
  -t enkryptai/secure-mcp-gateway:latest .
docker push enkryptai/secure-mcp-gateway:v2.2.1-1
docker push enkryptai/secure-mcp-gateway:latest

# Deploy (dev)
kubectx arn:aws:eks:us-east-1:188451452903:cluster/eks-dev
kubectl config current-context
kubectl diff  -f docs/secure-mcp-gateway-manifest.yaml -n dev
kubectl apply -f docs/secure-mcp-gateway-manifest.yaml -n dev
kubectl rollout status deploy/secure-mcp-gateway -n dev --timeout=300s

# Inspect
kubectl get deploy,svc,ingress -n dev -l app=secure-mcp-gateway
kubectl get deploy secure-mcp-gateway -n dev -o jsonpath='{.spec.template.spec.containers[0].image}{"\n"}'
kubectl logs deploy/secure-mcp-gateway -n dev -c config-downloader
kubectl logs deploy/secure-mcp-gateway -n dev -c secure-mcp-gateway -f
kubectl describe pod -n dev -l app=secure-mcp-gateway

# Config-only change
aws s3 cp enkrypt_mcp_config.json s3://mcpserver-enkryptai/enkrypt_mcp_config.json
kubectl rollout restart deploy/secure-mcp-gateway -n dev

# Rollback
kubectl rollout undo    deploy/secure-mcp-gateway -n dev
kubectl rollout history deploy/secure-mcp-gateway -n dev

# Reach the REST API (8001) on a live pod
kubectl port-forward -n dev deploy/secure-mcp-gateway 8001:8001
```

---

## 10. Related docs

- [CENTRALIZED_OAUTH_CALLBACK.md](../CENTRALIZED_OAUTH_CALLBACK.md) — remote OAuth callback checklist (`ENKRYPT_GATEWAY_BASE_URL`, ingress routing, replica constraint)
- [secure-mcp-gateway-manifest-example.yaml](../secure-mcp-gateway-manifest-example.yaml) — tracked template for the gitignored manifest
- [CLAUDE.md](../../CLAUDE.md) — architecture, hot-reload, timeouts, observability
- [observability/README.opensearch.md](../../observability/README.opensearch.md) — the OTLP → OpenSearch pipeline the OTel env vars feed
