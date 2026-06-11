# Local demo scan target (disabled by default)

A tiny, dependency-free web server used **only** as a safe, authorized target
for AutoBugHunter demos.

> ⚠️ **Authorized, isolated use only.** Run this only on your own machine in an
> isolated lab. It is intentionally *misconfigured* (missing security headers,
> verbose banner) so a baseline scan has benign findings to report — but it
> contains **no** exploitable vulnerabilities, payloads, or sensitive data.
> Never expose it to a network you do not control.

## Enable it

It is **off by default**. Start it explicitly via the compose profile:

```bash
docker compose --profile vuln up --build vulnerable-target
```

It listens on `http://localhost:9000`. To scan it, add it to a program's scope
(e.g. `domain: vulnerable-target` for in-container scanning, or `ip: 127.0.0.1`
/ `domain: localhost` from the host) and launch a `recon` scan. Set
`ALLOW_PRIVATE_TARGETS=true` only if scanning a private hostname is required in
your lab.
