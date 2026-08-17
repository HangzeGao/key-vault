# Access control user manual

The ground service accepts one fixed measurement host on the Data plane and one
local operations identity on the loopback Ops plane. Client authentication is a
256-bit bearer token; TLS 1.3 authenticates the server and protects the token in
transit. Source IP is an additional network constraint, not a second identity.

## 1. Generate credentials offline

Run as the account that controls deployment secrets. The command never prints
either token and refuses to overwrite an existing bundle:

```sh
go build -trimpath -o bin/kvlt-authgen ./cmd/kvlt-authgen
install -d -m 0700 /run/kvlt/generated-auth
bin/kvlt-authgen --output-dir /run/kvlt/generated-auth --tenant-id t-default
```

The output is:

| File | Destination | Secret |
| --- | --- | --- |
| `data.token` | fixed measurement application host | yes |
| `ops.token` | ground host, local `kvltctl` account | yes |
| `access-token-verifiers.json` | ground service host | no bearer secret, but integrity-sensitive |

Transfer token files using the mission's controlled administration channel.
Do not place tokens in command-line arguments, environment variables, tickets,
chat, logs or source control. Install them as regular non-symlink `0600` files.

## 2. Configure the service

```yaml
server:
  data_listen_addr: "192.0.2.10:8444" # exact local service interface
  ops_listen_addr: "127.0.0.1:8443"
  tls_cert_file: /run/kvlt/tls/server.crt
  tls_key_file: /run/kvlt/tls/server.key

auth:
  data_source_ip: "192.0.2.20" # exact measurement host address
  token_verifiers_file: /run/kvlt/secrets/access-token-verifiers.json
```

Production rejects wildcard Data listeners, CIDR source ranges, proxy-derived
addresses and missing verifier files. The Data connection must be direct: no
reverse proxy, load balancer or NAT may obscure `RemoteAddr`.

## 3. Enforce the source IP before TLS

The application repeats the exact-IP check after TLS, but only the host firewall
can reject unwanted peers before they consume TLS handshake resources. Example
`nftables` policy; replace interface, addresses and port with approved values:

```nft
table inet kvlt_filter {
  chain input {
    type filter hook input priority 0; policy drop;
    iifname "lo" accept
    ct state established,related accept
    iifname "mission0" ip saddr 192.0.2.20 tcp dport 8444 accept
  }
}
```

Do not let the service modify firewall rules dynamically. Firewall configuration
is deployment state reviewed independently from application configuration.

## 4. Call the Data plane

The measurement client pins the distributed server certificate and supplies the
Data token from its protected file. It must never use `-k` or `--insecure`:

```sh
curl --fail-with-body \
  --cacert /etc/measurement/key-vault-server.crt \
  -H 'Authorization: Bearer <contents-of-data.token>' \
  -H 'Content-Type: application/json' \
  --data @tc-protect-request.json \
  https://192.0.2.10:8444/api/v1/tc:protect
```

The client must read the token directly from its protected file and must not
place an expanded token in process arguments or tracing output.

A compilable Go client is provided at `examples/tc-protect-client`. It reads a
complete binary TC frame and creates a new protected-frame file without placing
the token on the command line:

```sh
go run ./examples/tc-protect-client \
  --addr https://192.0.2.10:8444 \
  --ca-file /etc/measurement/key-vault-server.crt \
  --token-file /run/measurement/data.token \
  --frame-file tc-frame.bin \
  --output-file tc-protected-frame.bin
```

Each `tc:protect` call allocates a fresh IV Counter. A link retransmission calls
protect again with the same complete plaintext TC frame and therefore receives a
new protected frame. The caller must preserve the TC frame sequence number;
FARM/COP-1 or the equivalent flight receive layer owns duplicate delivery
prevention.

## 5. Operate locally

```sh
export KVLT_OPS_ADDR=https://127.0.0.1:8443
export KVLT_OPS_TOKEN_FILE=/run/kvlt/secrets/ops.token
export KVLT_OPS_CA_FILE=/run/kvlt/tls/server.crt
kvltctl doctor
```

`kvltctl` refuses non-loopback destinations, redirects, symlink token files,
HTTPS without a pinned certificate, and TLS below 1.3. The status snapshot shows
aggregate source-IP, token, plane and rate-limit rejection counters without
persisting attacker-controlled events.

## 6. Rotate a token

There is no online issuer, grace state or dual-token window. In an approved
maintenance window:

1. Generate a complete new bundle in a new empty directory.
2. Stop new Data submissions.
3. Install the new Data token on the measurement host and the new verifier file
   on the ground host.
4. Restart the ground service.
5. Verify TLS, Data authentication and `kvltctl doctor`.
6. Remove the previous token files from controlled storage.

If a Token is suspected to be exposed, first block the Data port at the firewall,
then perform the same replacement. Never add a temporary second accepted token.
