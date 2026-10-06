#!/bin/sh
# Builds Dockerfile.app to GitLab Container Registry and, if GCP_PROJECT_ID + GCP_SA_KEY are set, to Google Artifact Registry.
set -eu
mkdir -p /kaniko/.docker
GL_AUTH=$(printf "%s:%s" "$CI_REGISTRY_USER" "$CI_REGISTRY_PASSWORD" | base64 | tr -d '\n')
AUTHS="\"${CI_REGISTRY}\":{\"auth\":\"${GL_AUTH}\"}"
DEST="--destination ${CI_REGISTRY_IMAGE}/app:${CI_COMMIT_SHORT_SHA} --destination ${CI_REGISTRY_IMAGE}/app:latest"
if [ -n "${GCP_PROJECT_ID:-}" ] && [ -n "${GCP_SA_KEY:-}" ]; then
  HOST="${GCP_REGION:-europe-west1}-docker.pkg.dev"
  GCP_AUTH=$(printf "_json_key:%s" "$(cat "$GCP_SA_KEY")" | base64 | tr -d '\n')
  AUTHS="${AUTHS},\"${HOST}\":{\"auth\":\"${GCP_AUTH}\"}"
  DEST="${DEST} --destination ${HOST}/${GCP_PROJECT_ID}/purrguard/app:${CI_COMMIT_SHORT_SHA}"
  echo "Artifact Registry: ${HOST}/${GCP_PROJECT_ID}/purrguard/app:${CI_COMMIT_SHORT_SHA}"
fi
echo "{\"auths\":{${AUTHS}}}" > /kaniko/.docker/config.json
# shellcheck disable=SC2086
exec /kaniko/executor --context "${CI_PROJECT_DIR}" --dockerfile "${CI_PROJECT_DIR}/Dockerfile.app" ${DEST}
