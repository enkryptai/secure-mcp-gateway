# Kubernetes Deployment Runbook — Secure MCP Gateway

**Audience**: DevOps / whoever is on release duty.
**Purpose**: Document how a change reaches dev and prod (CI image build, then
Argo CD), and keep the older hand-applied dev deploy as an emergency fallback.
**Last verified**: §1 and §7-§8 against this repo's workflows and the platform
repo's manifests on 2026-11-03 (gateway `2.2.5`); §2, §5 and §6 against the live
clusters on 2026-08-17 (gateway `v2.2.1-1`, before the Argo CD cutover).

---

## 1. Scope

| Aspect | Today |
| --- | --- |
| **Build** | CI builds the image from `Dockerfile` and pushes it to ECR: [svc-secure-mcp-gateway-dev.yaml](../../.github/workflows/svc-secure-mcp-gateway-dev.yaml) on pushes to `dev`, [svc-secure-mcp-gateway-prod.yaml](../../.github/workflows/svc-secure-mcp-gateway-prod.yaml) on pushes to `main`. Both sign the pushed digest with cosign and verify it. |
| **Deploy** | Argo CD, from the platform repo (`enkryptai-apiaas`, `code/infra/kubernetes/apps/secure-mcp-gateway/{base,dev,prod}`). Nothing is applied by hand. |
| **PyPI** | [publish.yml](../../.github/workflows/publish.yml) runs lint and tests on pushes to `main` and on `v*` tags, and publishes to PyPI only on a `v*` tag. It does not build or push the Docker image. |
| **Docker Hub** | The prod workflow also pushes the image it just pushed to ECR to `enkryptai/secure-mcp-gateway` as `v<version>`, `<version>` and `latest`, after checking that `version.py` and `pyproject.toml` agree (the job fails otherwise). This is what `secure-mcp-gateway --docker` pulls; the cluster does not use it. |
| **Where dev runs** | EKS `eks-dev`, region `us-east-1`, namespace **`dev`**. |
| **Where prod runs** | EKS `eks-prod`, same region, namespace **`production`**. Defined in the platform repo's `prod` overlay; see [§7](#7-prod-deployment). |

### 1.1 How a change reaches the clusters

1. **Release PR.** Bump `version` in `pyproject.toml` and `__version__` in
   [version.py](../../src/secure_mcp_gateway/version.py) together, and add the
   `CHANGELOG.md` entry. The workflows run only when `src/**`, `Dockerfile`,
   `requirements.txt`, `pyproject.toml`, `MANIFEST.in` or the workflow file
   itself changes — a docs-only change builds nothing.
2. **Dev.** A push to `dev` builds and pushes
   `enkryptai-dev/secure-mcp-gateway` to ECR with four tags: the 7-character
   commit SHA, an epoch timestamp, `dev`, and `dev-<epoch>`. Pull requests
   build the image but do not push it.
3. **Argo CD Image Updater** watches the `dev` tag by **digest**
   (`updateStrategy: digest`) and updates the Argo CD application when the
   digest moves. The base Deployment pins `…/enkryptai-dev/secure-mcp-gateway:dev`.
4. **Prod.** A push to `main` runs the same job against
   `enkryptai-prod/secure-mcp-gateway`, tagging `main`, SHA and epoch. The
   `prod` overlay patches the image to `…/enkryptai-prod/secure-mcp-gateway:main`
   and Image Updater follows that tag by digest too. The Docker Hub push runs in
   the same job, after cosign verification.
5. **PyPI.** Push a `v<version>` tag; `publish.yml` re-runs lint and tests
   and uploads with `--skip-existing`. PyPI and the Docker Hub tags are
   published by different triggers (tag vs. push to `main`), so a new CLI version
   can reach PyPI before its Docker Hub tag exists, or the other way round.

Both Argo CD applications (`dev` and `prod`) track the platform repo's `dev`
branch and run with automated sync, prune and self-heal. Dev and prod are
**separate builds** from different branches; prod is not a promotion of the
dev image.

---

## 2. Dev topology

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
  └── container      secure-mcp-gateway (<ECR registry>/enkryptai-dev/secure-mcp-gateway:dev)
        └── python src/secure_mcp_gateway/gateway.py  → :8000
```

### Resource ownership

Everything below is owned by Argo CD, from the platform repo's
`secure-mcp-gateway/{base,dev,prod}` kustomize tree:

| Resource | Source | Notes |
| --- | --- | --- |
| `ExternalSecret/s3-credentials` | `dev/`, `prod/` | Pulls the config-download credentials from the AWS secret store (`dev/…` and `prod/…` keys). See [§6.2](#62-static-aws-keys-for-the-config-download). |
| `Deployment/secure-mcp-gateway` | `base/` (+ `prod/` image patch) | The image is moved by Image Updater, not edited by hand. |
| `Service/secure-mcp-gateway-service` | `base/` | ClusterIP, port 80 → 8000. |
| `Ingress/mcp-server` | `dev/`, `prod/` | Traefik class; per-environment host. |
| `enkrypt_mcp_config.json` | S3, not in git | Pulled at pod start. **This is where telemetry, auth and guardrails are actually configured.** See [§5](#5-config-change-with-no-image-rebuild). |

The OTel env vars described in [§6.1](#61-the-otel-env-vars-on-the-deployment-are-inert)
were observed on the hand-applied Deployment; the base manifest does not define them.

The tracked `docs/secure-mcp-gateway-manifest-example.yaml` template (a Secret
with static keys, a Deployment pinned to a Docker Hub tag) predates this layout
and exists only for the manual fallback in [§4](#4-manual-dev-deploy-emergency-fallback-only).

---

## 3. Prerequisites for the manual fallback (one-time per operator)

Not needed for the normal CI and Argo CD path.

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

## 4. Manual dev deploy (emergency fallback only)

Use this only when CI or Argo CD cannot deploy. The dev application has
automated sync with self-heal, so a hand-applied change to the Argo-managed
Deployment is reverted unless the owner of Argo CD has paused sync for the
application first. Never use it to avoid a PR. The commands below are how dev was
deployed before the Argo CD cutover (verified 2026-08-17) and have not been
re-verified since.

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
kubectx arn:aws:eks:us-east-1:<account-id>:cluster/eks-dev
# ✔ Switched to context "arn:aws:eks:us-east-1:<account-id>:cluster/eks-dev".

kubectl config current-context      # confirm before every apply

kubectl apply -f docs/secure-mcp-gateway-manifest.yaml -n dev
```

Recommended: dry-run the diff first.

```bash
kubectl diff -f docs/secure-mcp-gateway-manifest.yaml -n dev
```

The only lines in that diff should be the image tag. A diff that also drops the
OTel env vars is harmless — they are inert
([§6.1](#61-the-otel-env-vars-on-the-deployment-are-inert)) — but anything else
unexpected is worth stopping for.

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

### 4.6 Rollback (manual fallback)

```bash
kubectl rollout undo deploy/secure-mcp-gateway -n dev
kubectl rollout status deploy/secure-mcp-gateway -n dev
```

Then revert the image tag in the manifest so the file matches the cluster.
Because every manual build gets a fresh tag, the previous ReplicaSet's image is
still pullable. Under Argo CD, roll back by reverting the change in git rather
than with `kubectl rollout undo`.

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

### 5.1 What the dev config actually contains

The dev object is the **cloud-backed minimal schema** (what
`generate-config --provider enkrypt` produces) — no `mcp_configs`, `projects`,
`users` or `apikeys` blocks, because the Enkrypt cloud owns those. It carries
exactly three things:

- `enkrypt_config` — cloud `base_url` (`http://gateway-kong`, the in-cluster
  Service, not the public `api.dev.enkryptai.com`), `api_key`, `org_id`
- `plugins.auth` / `plugins.guardrails` — both `provider: enkrypt`
- `plugins.telemetry` — `opentelemetry`, pointed at the in-cluster collector
  Service (this is the real telemetry config — see
  [§6.1](#61-the-otel-env-vars-on-the-deployment-are-inert))

There is **no `common_mcp_gateway_config` block**, so every setting in it —
log level, cache TTLs, `timeout_settings`, `enkrypt_gateway_base_url` — is
running on the [consts.py](../../src/secure_mcp_gateway/consts.py) defaults.
That's fine for most of them, but see [§6.7](#67-oauth-public-redirect-is-not-configured-in-dev)
for the one that isn't.

### 5.2 Do not `mv` the object

The init container hardcodes the key `enkrypt_mcp_config.json`. Renaming or
moving the object in S3 breaks the **next** pod start — the init container exits
1 and the pod never becomes ready (the running pod keeps serving from its
`emptyDir` copy, so the breakage stays invisible until something restarts it).

If you ever change the key name or prefix
([§7.2](#72-status-of-the-prod-checklist)), sequence it as
**copy → change the manifest → deploy → verify → delete the old key**, never a
bare move. The bucket has versioning enabled, so a mistaken delete is
recoverable, but a failed init container is still an outage on the next restart.

---

## 6. Known drift and gotchas

### 6.1 The OTel env vars on the Deployment are inert

As of 2026-08-17 the live Deployment carried 10 environment variables that were
**not** in the manifest and not in its `last-applied-configuration`. The
Argo-managed base manifest does not define them, so check the live object before
assuming they still exist:

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

They look load-bearing. **They are not — the gateway reads none of them.**
Telemetry is configured entirely from `plugins.telemetry.config` in the S3
config file:

| Env var | Why it has no effect |
| --- | --- |
| `OTEL_EXPORTER_OTLP_ENDPOINT`, `..._PROTOCOL` | [opentelemetry_provider.py](../../src/secure_mcp_gateway/plugins/telemetry/opentelemetry_provider.py) passes `endpoint=config["url"]` explicitly to `OTLPSpanExporter`/`OTLPLogExporter`/the metric exporter, and an explicit argument overrides the env var. |
| `OTEL_SERVICE_NAME` | Resolved as `config.get("service_name", "secure-mcp-gateway")`; the env var is never read. |
| `OTEL_RESOURCE_ATTRIBUTES` | The resource is built with the `Resource(attributes=…)` **constructor**, not `Resource.create()`, so the SDK's env-var resource detector never runs. `deployment.environment=dev` is **not** on the emitted telemetry. |
| `OTEL_TRACES_EXPORTER`, `OTEL_METRICS_EXPORTER`, `OTEL_LOGS_EXPORTER`, `OTEL_PYTHON_LOG_CORRELATION` | Only consulted under `opentelemetry-instrument` auto-instrumentation. This image wires the SDK by hand and has no `LoggingInstrumentor`. |
| `SKIP_DEPENDENCY_INSTALL` | Redundant. `is_docker()` returns True on `KUBERNETES_SERVICE_HOST`, which kubelet sets in every pod, so [gateway.py:94](../../src/secure_mcp_gateway/gateway.py) skips the pip install regardless. |
| `HOST_IP` | Exists only to interpolate into the inert endpoint above. |

The practical consequence: the env block names the node-local
`otel-collector-opentelemetry-collector-agent` DaemonSet, but the gateway
actually exports to the **ClusterIP Service**
`otel-collector-opentelemetry-collector.opentelemetry.svc.cluster.local:4317`
from the S3 config. Two different collectors — the config wins.

- **`kubectl apply` preserved the block** (three-way merge: fields in the live
  object but absent from both the last-applied annotation and the incoming file
  are left alone), so nothing changed either way.
- **Losing it costs nothing**, including on a first prod deploy — contrary to
  what the drift suggests.

**Action for DevOps**: delete the env block, or make it real. As it stands it
advertises an OTLP endpoint the gateway never contacts, which will send the next
person debugging missing telemetry to the wrong collector. And note that
`deployment.environment` / `k8s.namespace.name` are **not** reaching the backend
today — if you want them once prod also reports, they have to come from
`plugins.telemetry.config` or the provider has to switch to `Resource.create()`.
Setting them as env vars will not work.

### 6.2 Static AWS keys for the config download

Before the Argo CD cutover, `Secret/s3-credentials` was a hand-maintained,
gitignored file of base64 values on operator laptops. It is now an
`ExternalSecret` (dev and prod overlays) against the `aws-secret-store`
SecretStore, like the other apps in the namespace, so no credentials are kept in
git or on laptops.

The secret still carries long-lived `AWS_ACCESS_KEY_ID` /
`AWS_SECRET_ACCESS_KEY` values. **Remaining action for DevOps:** switch to
**IRSA** — a ServiceAccount annotated with an IAM role granting `s3:GetObject`
on the one config key, which removes the static keys entirely (the
`amazon/aws-cli` init container picks up the web-identity credentials with no
code change). The gitignored `docs/secure-mcp-gateway-manifest.yaml` is needed
only for the manual fallback.

### 6.3 Never reuse a tag

`imagePullPolicy` is unset, so it defaults to `IfNotPresent` for a pinned tag.
If you rebuild and re-push `v2.2.1-1`, nodes that already cached that tag keep
serving the **old** bits, and you get a half-upgraded fleet that is very hard to
diagnose. Always increment the build number.

CI deliberately breaks this rule for the moving tags: `dev` and `main` in ECR,
and `v<version>`, `<version>` and `latest` on Docker Hub, are re-pushed on every
qualifying build. The cluster is safe because Image Updater follows the digest
and Argo CD rolls the Deployment onto it. Anything that pins a Docker Hub tag
by name can see different bits after a rebuild at the same version.

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

### 6.6a Hosted gateways refuse stdio servers

The hosted gateway serves every tenant from one pod. A stdio server's `command`
would run inside that pod, next to the gateway's own API key and every other
tenant's sessions. The hosted Deployment therefore sets
`ENKRYPT_ALLOW_STDIO_SERVERS=false`, and only remote (`http`/`sse`) servers run
there. Stdio registry entries fail with `TRANS_009`, and the playground returns
`403`. Do not remove the env var until stdio servers run in real per-tenant
isolation.

### 6.7 OAuth public redirect is not configured in dev

`v2.2.1` shipped the public-URL redirect for remote gateway OAuth callbacks, but
the dev deployment sets **neither** `ENKRYPT_GATEWAY_BASE_URL` (no env on the
pod) **nor** `common_mcp_gateway_config.enkrypt_gateway_base_url` (no such block
in the S3 config, [§5.1](#51-what-the-dev-config-actually-contains)).

The gateway therefore falls back to `_request_derived_redirect()` in
[gateway_oauth_routes.py](../../src/secure_mcp_gateway/gateway_oauth_routes.py),
which reconstructs the callback from `X-Forwarded-Proto` / `X-Forwarded-Host`.
Traefik sets both by default, so this *probably* yields the correct
`https://mcp.dev.enkryptai.com/oauth2callback` today — but the code calls it a
"LAST-RESORT fallback ... don't depend on proxy header hygiene", and it has not
been verified end-to-end on this deployment.

Fix is one key in the S3 config:

```jsonc
{
  "common_mcp_gateway_config": {
    "enkrypt_gateway_base_url": "https://mcp.dev.enkryptai.com"
  },
  "enkrypt_config": { /* … unchanged … */ }
}
```

then `kubectl rollout restart deploy/secure-mcp-gateway -n dev`. Confirm the
advertised value before relying on it:

```bash
curl -sX POST https://mcp.dev.enkryptai.com/api/v1/oauth/authorize \
  -H "apikey: <GATEWAY_KEY>" -H "content-type: application/json" \
  -d '{"server_name": "<server>"}' | jq .redirect_uri
```

Whatever it returns must be registered verbatim with the IdP. **This becomes
mandatory in prod** — see [§7.2](#72-status-of-the-prod-checklist) item 5.

---

## 7. Prod deployment

Prod is defined in the platform repo (`secure-mcp-gateway/prod` overlay, Argo
CD application targeting namespace `production`) and built by the prod workflow
on pushes to `main` ([§1.1](#11-how-a-change-reaches-the-clusters)). A
2026-08-17 check found no `secure-mcp-gateway` in `eks-prod`; that predates the
overlay and has not been re-checked against the live cluster, so confirm there
before relying on this section.

### 7.1 What prod already provides (checked 2026-08-17)

| Dependency | Status in `eks-prod` |
| --- | --- |
| Namespace `production` | ✅ exists |
| IngressClass `nginx` (real ingress-nginx) | ✅ exists |
| IngressClass `traefik` | ✅ exists — used by every current prod app, and by this one |
| ClusterIssuer `letsencrypt-prod` | ✅ exists (TLS certs work the same way) |
| OTel agent DaemonSet on the node host IP | ✅ `otel-collector-opentelemetry-collector-agent`, ns `opentelemetry`, 15 nodes |
| ExternalSecrets operator | ✅ ns `external-secrets` exists |
| Node architecture | ✅ all 15 nodes `amd64` |

### 7.2 Status of the prod checklist

The original from-zero checklist, against the platform repo's current files:

1. **Hostname + Ingress.** Done: the `prod` overlay defines `Ingress/mcp-server`
   (`ingressClassName: traefik`, host `mcp.enkryptai.com`, path `/` so
   `/oauth2callback` works). The DNS record is outside git.
2. **S3 config key.** Done by bucket, not by prefix: the init container still
   copies the fixed key `enkrypt_mcp_config.json` from `${S3_BUCKET_NAME}`, and
   the bucket name comes from the per-environment secret (`prod/…`). Confirm
   that bucket holds the prod config, or prod boots on the wrong one.
3. **Credentials.** Done: `prod/external-secrets.yaml` reads the `prod/…` secret
   ([§6.2](#62-static-aws-keys-for-the-config-download)); IRSA is still open.
4. **Telemetry.** Open as configuration: it comes from `plugins.telemetry.config.url`
   in the prod S3 config, **not** from env vars
   ([§6.1](#61-the-otel-env-vars-on-the-deployment-are-inert)). The in-cluster
   Service `otel-collector-opentelemetry-collector.opentelemetry.svc.cluster.local:4317`
   exists in `eks-prod` too.
5. **`ENKRYPT_GATEWAY_BASE_URL`.** Open: the base Deployment sets no such env var.
   Set `common_mcp_gateway_config.enkrypt_gateway_base_url` in the prod S3 config
   to the public prod HTTPS URL and register `<base>/oauth2callback` with every IdP
   in use. Without it the gateway advertises a pod-IP redirect and OAuth fails.
6. **Resource requests/limits.** Open: the base Deployment declares none, so pods
   land in the `BestEffort` QoS class and are first to be evicted under node
   pressure.
7. **Probes.** Open: no `readinessProbe`/`livenessProbe`, so the Service sends
   traffic the moment the container process starts — before FastMCP is listening.
   A TCP socket probe on `:8000` is the simplest correct choice (`GET /` returns
   200 once the app is up).
8. **Replica strategy.** `replicas: 1` in the base manifest; keep it until OAuth
   pending-flow state is shared, or enable sticky sessions
   ([§6.4](#64-replicas-1-is-load-bearing-for-oauth)).

### 7.3 Prod deploy sequence

1. Merge the release into `main` (the dev-to-main PR; `no-commit-to-branch`
   blocks direct commits). The prod workflow builds, pushes and signs
   `enkryptai-prod/secure-mcp-gateway`, then pushes the Docker Hub tags.
2. Image Updater moves the `main` digest; Argo CD rolls the `production`
   Deployment. Watch the Argo CD application, then
   `kubectl rollout status deploy/secure-mcp-gateway -n production --timeout=300s`
   (read-only; confirm the context first).
3. Tag `v<version>` on the same commit to publish to PyPI.

Prod is a rebuild of `main`, not a promotion of the image tested in dev, so a
base-image or transitive-dependency change between the two builds can still
differ. Verify the prod image after the sync instead of assuming it matches dev.

No manual prod procedure is maintained. Do not `kubectl apply` into
`production`: the Argo CD application would revert it.

---

## 8. Pipeline notes

The pipeline that [§1.1](#11-how-a-change-reaches-the-clusters) describes is
what this section used to propose. What it still lacks:

- **No promotion gate.** Any qualifying push to `main` builds and ships the prod
  image; there is no manual approval between the dev rollout and prod.
- **No post-deploy check.** The workflows stop at cosign verification (and the
  Docker Hub push); nothing confirms the rollout became healthy.
- **No probes or resource limits** on the Deployment ([§7.2](#72-status-of-the-prod-checklist)).
- **The version check is prod-only.** `version.py` and `pyproject.toml` are
  compared only in the Docker Hub step of the prod workflow, so a mismatch on
  `dev` is not caught until the release reaches `main`.

---

## 9. Command quick reference

```bash
# Emergency fallback only: build + push (dev). Normal path: merge to dev, CI builds.
docker build --platform linux/amd64 \
  -t enkryptai/secure-mcp-gateway:v2.2.1-1 \
  -t enkryptai/secure-mcp-gateway:latest .
docker push enkryptai/secure-mcp-gateway:v2.2.1-1
docker push enkryptai/secure-mcp-gateway:latest

# Emergency fallback only: deploy (dev). Argo CD self-heal reverts it unless sync is paused.
kubectx arn:aws:eks:us-east-1:<account-id>:cluster/eks-dev
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

# Rollback (manual fallback)
kubectl rollout undo    deploy/secure-mcp-gateway -n dev
kubectl rollout history deploy/secure-mcp-gateway -n dev

# Reach the REST API (8001) on a live pod
kubectl port-forward -n dev deploy/secure-mcp-gateway 8001:8001
```

---

## 10. Related docs

- [svc-secure-mcp-gateway-dev.yaml](../../.github/workflows/svc-secure-mcp-gateway-dev.yaml), [svc-secure-mcp-gateway-prod.yaml](../../.github/workflows/svc-secure-mcp-gateway-prod.yaml), [publish.yml](../../.github/workflows/publish.yml) — the build, Docker Hub and PyPI workflows
- [CENTRALIZED_OAUTH_CALLBACK.md](../CENTRALIZED_OAUTH_CALLBACK.md) — remote OAuth callback checklist (`ENKRYPT_GATEWAY_BASE_URL`, ingress routing, replica constraint)
- [secure-mcp-gateway-manifest-example.yaml](../secure-mcp-gateway-manifest-example.yaml) — tracked template for the gitignored manifest
- [CLAUDE.md](../../CLAUDE.md) — architecture, hot-reload, timeouts, observability
- [observability/README.opensearch.md](../../observability/README.opensearch.md) — the OTLP → OpenSearch pipeline the OTel env vars feed
