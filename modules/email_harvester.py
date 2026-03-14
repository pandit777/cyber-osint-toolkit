import requests
import re

def harvest(url):

    if not url.startswith("http"):
        url = "https://" + url

    headers = {
        "User-Agent": "Mozilla/5.0"
    }

    try:
        r = requests.get(url, headers=headers, timeout=15)

        emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]+", r.text)

        print("\nEmails Found:\n")

        for email in set(emails):
            print(email)

        if len(emails) == 0:
            print("No emails found")

    except requests.exceptions.Timeout:
        print("Request timed out. Website slow or blocking request.")

    except Exception as e:
        print("Error:", e)