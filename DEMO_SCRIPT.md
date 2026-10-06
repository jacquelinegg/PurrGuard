# Demo script (under 3 minutes) — Hands-off cycle

Prepare beforehand: fresh project, `rotate --ttl-days 3` already committed (SETUP.md step 6), open tab with Pipelines. No music and no third-party branding.

1. **0:00 The problem (15 s).** "Agents read the repo and logs. Secrets leak and expirations leak."
2. **0:15 Sealing (20 s).** Show `logo.png` before/after (visually identical), `strings logo.png | grep -i token` → nothing. "Security is AES-GCM + key; the image is camouflage."
3. **0:35 Protection (25 s).** MR with replaced logo → `purrguard-mr` fails (`carrier_tampered`).
4. **1:00 Start the cycle (10 s).** Run pipeline on `main`. "From here I don't touch anything."
5. **1:10 Rotation (35 s).** `expiry-watch` → issue; `rotate-secrets` (the only one with the key) → MR `stegoops/rotate-…`; `rotation-guard` + PurrGuard green → merges automatically.
6. **1:45 Deploy (30 s).** `build-app` → `deploy-staging`: in the logs `canary: ***`, `leak_audit.json` → `clean`. Then `deploy-cloudrun` and open the public URL.
7. **2:15 The agent (30 s).** Deploy Sentinel (from pipeline event) → note in the issue: secrets (names only), 0 exfiltrations. "The agent has seen neither the key nor the raw logs."
8. **2:45 Honesty (10 s).** "Agents verify and report; privileged steps are deterministic CI."
