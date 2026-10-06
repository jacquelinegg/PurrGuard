#!/usr/bin/env bash
# Google Cloud Run deploy. Secrets stay in memory -> Secret Manager -> Cloud Run --set-secrets
# (not --set-env-vars, so they do not appear in command line/console).
# SRC_IMAGE = GitLab registry image (carrier read from here); RUN_IMAGE = Artifact Registry image (Cloud Run executes this).
set -euo pipefail
: "${GCP_PROJECT_ID:?}" "${SRC_IMAGE:?}" "${RUN_IMAGE:?}"
REGION="${GCP_REGION:-europe-west1}"
python -m stegoops exec --from-image "$SRC_IMAGE" --path app/assets/logo.png --fallback-local -- python deploy/push_secrets_gcp.py
gcloud run deploy purrguard-stegoops --image "$RUN_IMAGE" --region "$REGION" --project "$GCP_PROJECT_ID" \
  --allow-unauthenticated --port 8080 \
  --set-secrets "DEMO_DB_PASSWORD=demo-db-password:latest,DEMO_API_TOKEN=demo-api-token:latest"
URL=$(gcloud run services describe purrguard-stegoops --region "$REGION" --project "$GCP_PROJECT_ID" --format='value(status.url)')
echo "$URL" > cloudrun_url.txt
echo "Cloud Run: $URL"
curl -fsS "$URL/health"; echo
