# API Middleware

Order is request ID → body limit/read → authentication → API plane/scope matrix → capacity guard → handler. Strict JSON rejects unknown and duplicate fields at any depth. The admission guard limits crypto, batch, list, hot-key, and Ops traffic per process; production also requires a distributed gateway limit.
