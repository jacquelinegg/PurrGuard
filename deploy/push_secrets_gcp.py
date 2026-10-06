"""Reads secrets from the environment (provided by stegoops exec) and writes them to GCP Secret Manager. Not tested here."""
import os

from google.cloud import secretmanager

project = os.environ["GCP_PROJECT_ID"]
c = secretmanager.SecretManagerServiceClient()
for env_name, sid in (("DEMO_DB_PASSWORD", "demo-db-password"), ("DEMO_API_TOKEN", "demo-api-token")):
    parent, name = f"projects/{project}", f"projects/{project}/secrets/{sid}"
    try:
        c.get_secret(request={"name": name})
    except Exception:
        c.create_secret(request={"parent": parent, "secret_id": sid, "secret": {"replication": {"automatic": {}}}})
    c.add_secret_version(request={"parent": name, "payload": {"data": os.environ[env_name].encode()}})
    print("Secret Manager updated:", sid)
