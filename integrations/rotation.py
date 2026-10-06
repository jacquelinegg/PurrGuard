"""Compromised key rotation plan. Commands are templates; nothing runs automatically."""

PLAYS = {
    "gcp_service_account": lambda s: [
        "GCP service account key - disable then delete:",
        f"```\ngcloud iam service-accounts keys disable {s.get('key_id')} --iam-account={s.get('email')}\n"
        f"gcloud iam service-accounts keys delete {s.get('key_id')} --iam-account={s.get('email')}\n```"],
    "gcp_api_key": lambda s: ["GCP API key - find and delete:",
                              "```\ngcloud services api-keys list\ngcloud services api-keys delete KEY_UID\n```"],
    "aws_access_key": lambda s: ["AWS access key - deactivate and create new:",
                                 "```\naws iam update-access-key --access-key-id <ID> --status Inactive --user-name <USER>\n"
                                 "aws iam create-access-key --user-name <USER>\n```"],
    "gitlab_token": lambda s: ["GitLab token - revoke in Settings > Access tokens (or `DELETE /personal_access_tokens/:id`)."],
    "anthropic_key": lambda s: ["Anthropic API key - revoke in Console and create new."],
    "private_key": lambda s: ["Private key - generate new keypair and remove old public key from all `authorized_keys`/servers."],
    "generic_secret": lambda s: ["Unknown secret type - rotate with provider and check logs for usage."],
}


def playbook(findings):
    seen, lines = set(), []
    for f in findings:
        for s in f.get("secrets", []):
            key = (s["type"], s.get("key_id"))
            if key in seen or s["type"] not in PLAYS:
                continue
            seen.add(key)
            lines += PLAYS[s["type"]](s)
    if lines:
        lines += ["Finally: check logs for key usage and clean git history (`git filter-repo`)."]
    return "\n\n".join(lines)
