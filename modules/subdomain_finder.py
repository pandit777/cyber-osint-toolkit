import requests

def find(domain):

    subdomains = [
        "www",
        "mail",
        "ftp",
        "webmail",
        "admin",
        "test",
        "dev",
        "blog",
        "shop"
    ]

    print("\nScanning subdomains...\n")

    for sub in subdomains:

        url = f"http://{sub}.{domain}"

        try:
            requests.get(url, timeout=2)
            print(f"[+] Found: {url}")

        except:
            pass