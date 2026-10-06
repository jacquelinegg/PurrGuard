import os

import requests


def slack(text):
    url = os.environ.get("SLACK_WEBHOOK_URL")
    if not url:
        return
    try:
        requests.post(url, json={"text": text}, timeout=15)
    except requests.RequestException as e:
        print("[slack] неуспешно:", e)
