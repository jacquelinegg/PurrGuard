#!/usr/bin/env bash
# One-time setup: prepares GCP for deploy-cloudrun. Do not store key in repo.
set -euo pipefail
: "${GCP_PROJECT_ID:?set GCP_PROJECT_ID}"
REGION="${GCP_REGION:-europe-west1}"
SA="purrguard-ci"
SA_EMAIL="${SA}@${GCP_PROJECT_ID}.iam.gserviceaccount.com"
gcloud config set project "$GCP_PROJECT_ID"
gcloud services enable run.googleapis.com artifactregistry.googleapis.com secretmanager.googleapis.com iam.googleapis.com
gcloud artifacts repositories describe purrguard --location "$REGION" >/dev/null 2>&1 || \
  gcloud artifacts repositories create purrguard --repository-format=docker --location "$REGION"
gcloud iam service-accounts describe "$SA_EMAIL" >/dev/null 2>&1 || gcloud iam service-accounts create "$SA" --display-name "PurrGuard CI"
for role in roles/run.admin roles/artifactregistry.writer roles/secretmanager.admin roles/iam.serviceAccountUser; do
  gcloud projects add-iam-policy-binding "$GCP_PROJECT_ID" --member "serviceAccount:${SA_EMAIL}" --role "$role" --condition=None >/dev/null
done
# Cloud Run reads secrets via its default identity (compute SA)
PROJECT_NUMBER=$(gcloud projects describe "$GCP_PROJECT_ID" --format='value(projectNumber)')
gcloud projects add-iam-policy-binding "$GCP_PROJECT_ID" --member "serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
  --role roles/secretmanager.secretAccessor --condition=None >/dev/null
gcloud iam service-accounts keys create purrguard-ci-key.json --iam-account "$SA_EMAIL"
cat <<MSG

Done. Next:
 1) GitLab -> Settings -> CI/CD -> Variables:
       GCP_PROJECT_ID = ${GCP_PROJECT_ID}     GCP_REGION = ${REGION}
       GCP_SA_KEY     = (File type) contents of purrguard-ci-key.json   [protected]
 2) Delete file:  shred -u purrguard-ci-key.json  (or rm)
 3) Push to default branch -> build-app -> deploy-staging -> deploy-cloudrun. URL: cloudrun_url.txt in artifacts.
 MSG
