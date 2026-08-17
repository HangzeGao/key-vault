# API Middleware

Data execution order is exact RemoteAddr allowlist → request ID → pre-auth admission → bearer verifier → plane/scope matrix → authenticated admission → body limit/read → handler. Forwarded client-IP headers are unsupported. Ops is bound to loopback and starts at request ID. Strict JSON rejects unknown and duplicate fields at any depth.
