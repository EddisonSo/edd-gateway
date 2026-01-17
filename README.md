# edd-gateway

Layer 7 proxy service for routing SSH, HTTP, and HTTPS traffic to user containers based on hostname, SNI, and username.

## Overview

The gateway is the entry point for all container traffic in edd-cloud. It routes incoming connections to the appropriate container by inspecting protocol-specific identifiers:

- **SSH**: Routes by username (format: `containerid` or `user.containerid`)
- **HTTP**: Routes by `Host` header (format: `containerid.compute.cloud.eddisonso.com`)
- **HTTPS/TLS**: Routes by SNI (Server Name Indication) - TLS passthrough, no termination

## Architecture

```
                      Internet
                          │
                   ┌──────┴──────┐
                   │   MetalLB   │
                   │LoadBalancer │
                   └──────┬──────┘
                          │
        ┌─────────────────┼─────────────────┐
        │                 │                 │
   Port 22           Port 80/443      Port 8000-8999
   (SSH)            (HTTP/HTTPS)      (Multi-protocol)
        │                 │                 │
        └─────────────────┼─────────────────┘
                          │
                   ┌──────┴──────┐
                   │   Gateway   │
                   │   Service   │
                   └──────┬──────┘
                          │
               ┌──────────┼──────────┐
               │          │          │
               ▼          ▼          ▼
         Container    Container    Fallback
         Pod (K8s     Pod (K8s    Upstream
         Service)     Service)   (Traefik)
```

## Features

- **Protocol Detection**: Ports 8000-8999 auto-detect SSH, HTTP, or TLS from first bytes
- **TLS Passthrough**: HTTPS connections are proxied without termination - certificates are handled by the container
- **SSH Proxying**: Full SSH channel proxying with support for shell, exec, and port forwarding
- **Dynamic Port Mapping**: Ingress rules map external ports to container target ports
- **In-Memory Cache**: Container routing table cached with 5-second sync from PostgreSQL
- **Fallback Upstream**: Non-container traffic routes to a configurable upstream (e.g., Traefik)
- **Gateway SSH Key**: Auto-generated ed25519 key stored in K8s Secret for container authentication

## Configuration

### Command Line Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-ssh-port` | `22` | SSH proxy listen port |
| `-http-port` | `80` | HTTP proxy listen port |
| `-https-port` | `443` | HTTPS/TLS proxy listen port |
| `-fallback` | `""` | Fallback upstream address (e.g., `192.168.3.150`) |
| `-log-service` | `""` | gRPC log service address |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | PostgreSQL connection string |

## Database Schema

The router queries PostgreSQL for container routing information:

```sql
-- Container records
SELECT id, namespace, external_ip, status, ssh_enabled, https_enabled
FROM containers
WHERE status = 'running' AND external_ip IS NOT NULL

-- Port mapping rules
SELECT container_id, port, target_port
FROM ingress_rules
```

## SSH Routing

SSH connections use the username to determine routing:

```bash
# Connect as root to container abc123
ssh abc123@gateway.example.com

# Connect as 'dev' user to container abc123
ssh dev.abc123@gateway.example.com
```

The gateway:
1. Performs SSH handshake with client
2. Extracts container ID from username
3. Resolves container via router (checks SSH enabled)
4. Connects to container using K8s service DNS (`lb.<namespace>.svc.cluster.local`)
5. Authenticates using gateway's ed25519 key (stored in `gateway-ssh-key` Secret)
6. Proxies SSH channels bidirectionally

## HTTP/HTTPS Routing

HTTP and HTTPS use hostname-based routing:

```
https://abc123.compute.cloud.eddisonso.com/
        └─────┘
      container ID extracted from first subdomain
```

For non-standard ports, the router uses the `ingress_rules` table to map ingress port to target port:

```
https://abc123.compute.cloud.eddisonso.com:8888/
                                          └───┘
                                    looks up ingress_rules
                                    port 8888 -> target port
```

## Kubernetes Deployment

The gateway runs as a Deployment with:
- ServiceAccount with RBAC for secret management
- LoadBalancer Service via MetalLB
- Ports: 22 (SSH), 80 (HTTP), 443 (HTTPS), 8000-8999 (dynamic)

### RBAC Permissions

The gateway ServiceAccount needs:
- `get`, `create`, `update`, `patch` on `secrets` (for gateway-ssh-key)

### Service Ports

The LoadBalancer exposes:
- Port 22 -> Container port 2222 (SSH)
- Port 80 -> Container port 8080 (HTTP)
- Port 443 -> Container port 8443 (HTTPS)
- Ports 8000-8999 -> Same container ports (multi-protocol)

## Building

```bash
# Build binary
go build -o gateway .

# Build Docker image
docker build -t eddisonso/ecloud-gateway:latest .
```

## Deployment

```bash
# Apply Kubernetes manifests
kubectl apply -f manifests/gateway.yaml

# Check status
kubectl get pods -l app=gateway
kubectl logs -l app=gateway
```

## Protocol Detection

On ports 8000-8999, the gateway reads the first bytes to detect protocol:

| First Bytes | Protocol |
|-------------|----------|
| `SSH-` | SSH |
| `0x16` | TLS |
| `GET `, `POST`, etc. | HTTP |

## Gateway SSH Key

On startup, the gateway:
1. Tries to load ed25519 key from `gateway-ssh-key` Secret
2. If not found, generates new key and creates Secret
3. Public key is injected into container `authorized_keys` by edd-compute

The Secret contains:
- `private_key`: PEM-encoded ed25519 private key
- `public_key`: OpenSSH authorized_keys format public key
