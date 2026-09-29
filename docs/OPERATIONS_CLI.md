# Operations without a web frontend

`kvltctl` is the supported read-only operations interface. The operations
listener must bind an explicit loopback address and still requires a
tenant-bound bearer token with `ops:read` and/or `audit:read` scope. Store that
token in a regular file readable only by its owner (`0600` on Unix).

```sh
export KVLT_OPS_ADDR=https://127.0.0.1:8443
export KVLT_OPS_TOKEN_FILE=/etc/key-vault/ops.token
export KVLT_OPS_CA_FILE=/etc/key-vault/server.crt

kvltctl status
kvltctl status --json
kvltctl doctor
kvltctl audit tail --limit 50
kvltctl audit verify
```

Exit status is stable and suitable for monitoring:

| Code | Meaning |
|---:|---|
| 0 | READY / audit intact |
| 1 | DEGRADED or unconfigured |
| 2 | operations listener unreachable |
| 3 | audit chain corrupt |
| 4 | invalid configuration or rejected credential |

`GET /healthz` is unauthenticated process liveness only. `GET
/ops/v1/status` is the consolidated readiness snapshot. Audit reads are
`GET /ops/v1/audit/events`, `GET /ops/v1/audit/verify`, and `GET
/ops/v1/audit/heads`. There are no mutation endpoints on the operations
listener.

`kvltctl` accepts only an explicit loopback origin. HTTPS requires `--ca-file`
or `KVLT_OPS_CA_FILE`; redirects and TLS versions below 1.3 are rejected. The
status JSON includes aggregate `access_rejections` counters and no token or
source-address values.

Use the service manager for lifecycle and logs:

```sh
systemctl status key-vault
journalctl -u key-vault -f
systemctl restart key-vault
```

Provisioning and key transitions remain explicit offline tools:
`ccsds-provision` and `ccsds-activate`.
