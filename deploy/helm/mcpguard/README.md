# MCPGuard Helm Chart

Enterprise-grade Helm chart for deploying **MCPGuard** (Zero-Trust Security Gateway for Model Context Protocol Agents) on Kubernetes.

---

## Architecture Overview

The MCPGuard Helm chart deploys a highly available, zero-trust MCP proxy stack with:
- **Zero-Trust Hardening**: Complies with Kubernetes Restricted Pod Security Standards (`runAsNonRoot: true`, `readOnlyRootFilesystem: true`, `drop: ["ALL"]`, `seccompProfile: RuntimeDefault`).
- **Dual-Port Isolation**:
  - `8080`: Agent MCP Gateway traffic (`/mcp`, `/healthz`).
  - `8081`: Admin, HITL approvals, and Prometheus metrics scraping (`/metrics`, `/admin/*`).
- **Autoscaling & High Availability**: HorizontalPodAutoscaler (HPA) and PodDisruptionBudget (PDB) configured by default with inter-pod anti-affinity.
- **Micro-segmentation**: Zero-Trust `NetworkPolicy` restricting ingress and egress, blocking AWS/GCP/Azure link-local metadata endpoints (`169.254.169.254`).
- **Declarative Policy Management**: Hot-reloadable `shield.yaml` and `policy.yaml` mounted via Kubernetes ConfigMaps.

---

## Quickstart

### 1. Add Repository & Install

```bash
# Add repo or use local directory
helm install mcpguard ./deploy/helm/mcpguard \
  --namespace mcpguard \
  --create-namespace \
  --set secrets.adminToken="YOUR_SECURE_ADMIN_TOKEN" \
  --set secrets.jwtHs256Secret="YOUR_32_CHAR_JWT_SECRET_KEY"
```

### 2. Verify Deployment

```bash
kubectl get pods -n mcpguard -l app.kubernetes.io/name=mcpguard
kubectl get svc -n mcpguard
```

---

## Configuration Parameters

| Parameter | Description | Default |
|---|---|---|
| `replicaCount` | Number of gateway replicas | `2` |
| `image.repository` | Container image repository | `mcpguard/shield` |
| `image.tag` | Container image tag | `0.1.0` (Chart appVersion) |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `serviceAccount.create` | Create a dedicated ServiceAccount | `true` |
| `serviceAccount.automountServiceAccountToken` | Mount k8s API token into container | `false` (Zero-Trust) |
| `podSecurityContext.runAsUser` | UID to run the gateway process | `65532` (nonroot) |
| `podSecurityContext.runAsGroup` | GID to run the gateway process | `65532` |
| `securityContext.readOnlyRootFilesystem` | Read-only container rootfs | `true` |
| `securityContext.capabilities.drop` | Dropped Linux capabilities | `["ALL"]` |
| `service.type` | Kubernetes service type | `ClusterIP` |
| `service.mcpPort` | Service port for MCP gateway | `8080` |
| `service.adminPort` | Service port for admin / metrics | `8081` |
| `autoscaling.enabled` | Enable HorizontalPodAutoscaler | `true` |
| `autoscaling.minReplicas` | Minimum HPA replicas | `2` |
| `autoscaling.maxReplicas` | Maximum HPA replicas | `10` |
| `autoscaling.targetCPUUtilizationPercentage` | Target CPU threshold | `75` |
| `autoscaling.targetMemoryUtilizationPercentage` | Target Memory threshold | `80` |
| `podDisruptionBudget.enabled` | PodDisruptionBudget enabled | `true` |
| `podDisruptionBudget.minAvailable` | Minimum available pods during eviction | `1` |
| `networkPolicy.enabled` | Zero-Trust NetworkPolicy | `true` |
| `networkPolicy.egress.blockMetadata` | Block egress to `169.254.169.254/32` | `true` |
| `serviceMonitor.enabled` | Prometheus Operator ServiceMonitor | `false` |
| `secrets.existingSecret` | Name of pre-existing secret (e.g. from Vault/SealedSecrets) | `""` |
| `secrets.adminToken` | Admin token if not using external secret | `change-me-...` |
| `secrets.jwtHs256Secret` | JWT secret if not using external secret | `change-me-...` |

---

## Production Security Best Practices

### Using External Secrets (HashiCorp Vault / AWS Secrets Manager)

Instead of passing secrets directly in `values.yaml`, create a Kubernetes Secret using your external secrets operator and point the Helm chart to it:

```yaml
secrets:
  existingSecret: "mcpguard-vault-secrets"
```

The secret must contain the following keys:
- `admin-token`: The administrative bearer token.
- `jwt-hs256-secret`: The HMAC key for agent tokens (if using HS256 auth mode).

### Policy Hot-Reload

When `config.policyYaml` is updated in `values.yaml` and re-deployed via `helm upgrade`, the ConfigMap checksum changes triggering a rolling update of MCPGuard pods, ensuring zero downtime and validation before deployment.

