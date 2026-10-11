# SETUP — from zero to a working demo project

The hackathon deadline is **27 October 2026, 13:00 UTC**. Path: **Path A (Start Fresh)**, level: **Hands-off**.

## 0. Prerequisites
- Devpost registration for the hackathon + GitLab contributor onboarding (https://contributors.gitlab.com/transcend-hackathon, approval takes ~24 h).
- Your GitLab project must have Duo Agent Platform enabled (AI > Flows should be visible in the sidebar).
- Locally: Python 3.12, git. For Google Cloud: `gcloud` (or Cloud Shell) and billing enabled on the project.

## 1. Local check (5 min)
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python tests/test_purrguard.py && python tests/test_stegoops.py && python tests/test_autopilot.py
python -m stegoops init-demo
```
`init-demo` creates a logo, seals 2 **FAKE** secrets, and **prints `STEGOOPS_KEK` only once** — copy it (you will put it in GitLab). Do not commit it.
The result is a modified `app/assets/logo.png` and `.stegoops/manifest.json`: **commit both**.

## 2. GitLab project
1. New **public** empty project. (The MIT license is in `LICENSE`; verify it is visible in About.)
2. CODEOWNERS: replace `@security-owners` with your user or an existing group.
3. **Before the first push** configure the variables below, otherwise `deploy-staging` will fail.

### Settings
| Where | What |
|---|---|
| Settings > Repository > Protected branches | `main` is protected. **Allowed to merge: Developers + Maintainers** (so the bot can merge). Leave "Require approval from Code Owners" disabled — otherwise auto-merge waits for a human. Compensating controls: `rotation-guard`, PurrGuard, "Pipelines must succeed" |
| Settings > Merge requests | enable **Pipelines must succeed** |
| Settings > Access tokens | token `purrguard-bot`, role **Developer**, scope **api**. Copy the value |
| Settings > CI/CD > Variables | `STEGOOPS_KEK` = the key from step 1 — **Masked + Protected, Environment scope: `staging`** |
| | `GITLAB_API_TOKEN` = the token — **Masked + Protected**, scope: All |
| Deploy > Container Registry | enabled (by default) |

### First push
```bash
git init -b main && git add -A && git commit -m "PurrGuard + Stego-Ops"
git remote add origin https://gitlab.com/gitlab-ai-hackathon/transcend-october-2026/43043338/showcase.git
git push -u origin main
```
Expected: `tests`, `stegoops-verify` → `build-app` → `deploy-staging` (in logs: `canary (should be ***): ***`; artifact `leak_audit.json`, verdict `clean`).
If the registry client fails, `--fallback-local` prints a warning and continues with the pinned local carrier — the deploy still passes.

## 3. Google Cloud (bonus up to +0.2 points)
In Cloud Shell or locally, after `gcloud auth login`:
```bash
export GCP_PROJECT_ID=<your-project>   # optional: export GCP_REGION=europe-west1
bash deploy/gcp_setup.sh
```
The script enables APIs, creates an Artifact Registry repo `purrguard`, a service account `purrguard-ci` with the needed roles, and a key `purrguard-ci-key.json`.
Then in GitLab (Settings > CI/CD > Variables):
- `GCP_PROJECT_ID`, `GCP_REGION` (regular);
- `GCP_SA_KEY` — type **File**, content: the entire JSON, **Protected**.
Delete the local key (`shred -u purrguard-ci-key.json`). The next push to `main` triggers `deploy-cloudrun`; the public address is in the logs and in the `cloudrun_url.txt` artifact — put that in Devpost.
If `--allow-unauthenticated` is blocked by organizational policy, public access must be enabled (the jury needs a public link).
Better production practice: Workload Identity Federation instead of a key (left as a next step).

## 4. Duo flows
1. AI > Flows > New flow → upload `duo/flows/stegoops-mr-guardian.yaml`; triggers: **mention** (and optionally assign/reviewer of the flow).
2. New flow → upload `duo/flows/stegoops-deploy-sentinel.yaml`; triggers: **Pipeline** (should trigger on pipeline events) and **mention**..
3. The Flow builder validates the YAML. **Small corrections are expected here**: tool names in `toolset` (`create_issue`, `create_issue_note`, `gitlab_api_get`, `get_merge_request`, …) and allowed fields depend on the version. Fix whatever it complains about and return the fix to the repo.
4. The flow's service account must be a member of the project (Developer) to comment.
5. MCP: `.gitlab/duo/mcp.json` registers the `purrguard` MCP server. Check in your version where it applies (e.g. Duo Chat in IDE). Mention it in the submission only if you show it in the video.

## 5. Schedule (for the automatic cycle)
Build > Pipeline schedules > New schedule: every day, target branch `main`. It runs `expiry-watch`, `rotate-secrets`, `purrguard-history`, and `pages`.

## 6. Cycle demo (now, without waiting 30 days)
```bash
export STEGOOPS_KEK=<the-key>
python -m stegoops rotate --carrier app/assets/logo.png --ttl-days 3   # shortens the TTL to 3 days
git add -A && git commit -m "demo: short TTL" && git push
```
Wait for the push pipeline, then Build > Pipelines > **Run pipeline** on `main`. Watch:
1. `expiry-watch` opens an issue with label `stegoops::rotation`;
2. `rotate-secrets` opens MR `stegoops/rotate-…` with auto-merge;
3. the MR pipeline (`rotation-guard`, `purrguard-mr`, `stegoops-verify`, `tests`) passes and the MR merges automatically;
4. `build-app` → `deploy-staging` → `deploy-cloudrun`;
5. Deploy Sentinel publishes the result in the issue.

Tampered carrier test: new branch with a different `logo.png` → MR → `purrguard-mr` fails (`carrier_tampered`). Leave this MR open — visible pipeline history is needed.

## 7. Submission
- Fill in `DEVPOST.md`: repo link, YouTube video (< 3 min, no third-party branding or music), Cloud Run link.
- Choose **Path A** and level **Hands-off**; optionally — Google Cloud bonus (the link must be public until winners are announced).
- Repository security: if you suspect the KEK has been exposed, rotate it (`keygen`, new `seal`) before making the project public.
