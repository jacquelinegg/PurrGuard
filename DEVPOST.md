# Devpost submission text (English)

**Title:** PurrGuard · Stego-Ops — secrets your AI agents can't leak, because they never hold the key

**Path / level:** Path A (Start Fresh) · Hands-off (with a supervised MR flow as a second, optional entry point)

## Problem
AI agents read repos, run commands and write logs. Plain-text secrets in env fields, `.env` files or CI output end up in agent context, MR comments and job logs. Secrets also expire, and rotation is exactly the chore people postpone. We want a loop that rotates, ships and verifies on its own **without ever giving an agent the key**.

## What it does
**Stego-Ops** encrypts deployment secrets (AES-256-GCM, envelope key wrapped by a KEK from a protected CI variable or Cloud KMS) and hides the ciphertext in a normal PNG asset (key-derived pseudo-random LSB positions). The image ships in the GitLab Container Registry. At deploy time the pipeline extracts and decrypts **in memory only**, injects secrets into the child process environment, and scrubs the logs. The KEK is never passed to the child. Steganography is camouflage (keeps ciphertext out of scanners and LLM context); security comes from AES-GCM and the key.

**PurrGuard** scans merge requests for hidden exfiltration (steganography, invisible Unicode, honeytokens) and pins legitimate carriers by SHA-256 from a *trusted* revision, so it isn't blinded by its own product.

### The hands-off loop (no human in the middle)
1. A scheduled pipeline (`expiry-watch`, no key) detects a bundle nearing expiry and opens an issue.
2. `rotate-secrets` — the **only** job holding the KEK — re-seals the carrier, opens a branch, commits the new carrier + manifest through the API, opens an MR and enables auto-merge.
3. `rotation-guard` fails the pipeline if the MR touches anything but carriers and manifest; PurrGuard + verify + tests must pass, otherwise nothing merges.
4. Merge triggers `build-app` → `deploy-staging` (in-memory secrets, scrubbed logs, deterministic `leak_audit.json`) → optional `deploy-cloudrun` on Google Cloud.
5. **GitLab Duo flow "Deploy Sentinel"** is triggered by the pipeline event: preflight (manifest, expiry, deploy job), reads only the audit counters (never raw logs), and reports on the rotation issue — or opens an issue naming the secrets to rotate if anything leaked.

A second flow, **MR Guardian** (supervised), scans MRs, plans remediation, waits at one approval gate and opens a fix MR. A small read-only **MCP server** exposes `verify`, `expiry` and `scan` (names and dates only).

## Agents hold no privilege — by design
Agents decide and report; privileged actions (rotation, merge, deploy) are deterministic CI steps. An agent compromised by prompt injection has no key, no raw logs and no merge power.

## Lifecycle stages
Plan (issues, flow triggers) · Create (rotation/fix MRs) · Verify (tests, guards) · Package (Container/Artifact Registry) · Secure (PurrGuard, honeytokens, carrier pinning) · Release (staging + Cloud Run) · Configure (agent config, KEK scoping, Secret Manager) · Monitor (leak audit, Cloud Logging, Pages dashboard) · Govern (manifest, CODEOWNERS, expiry, audit trail).

## How we built it
Python (cryptography, Pillow, numpy), GitLab CI + Kaniko + Container Registry, GitLab Duo Agent Platform custom flows and MCP, Google Cloud (Artifact Registry, Secret Manager, Cloud Run).

## What we tested
80+ automated checks (3 suites): round-trip, wrong key, tampered/swapped carrier, GCM integrity, expiry, rotation wipes old ciphertext, scrubber, in-memory registry extraction (fake registry), carrier/PurrGuard interplay, decoy honeytokens, full rotation flow against a fake GitLab API (issue dedup, branch, commit contents, MR, auto-merge retries), rotation guard on a real git repo, registry-outage fallback, MCP protocol, and structural validation of flows and CI.

## Honest limits
Steganography is fragile (recompression breaks it) and is not the security boundary. Anyone who can run code in the deploy job can read its secrets (as with any CI secret); mitigations are protected branches, environment scoping and KMS. Auto-merge replaces CODEOWNERS approval for rotation MRs; we compensate with the guard job and required pipelines. Details in the README.

## What's next
Signed manifests, Workload Identity Federation instead of a service-account key, per-environment KEKs.

> Fill in before submitting: repo URL, pipeline history, YouTube demo link, Cloud Run URL.
