import phonenumbers
from phonenumbers import geocoder, carrier
import requests

sites = {
    "Instagram": "https://www.instagram.com/{}",
    "Facebook": "https://www.facebook.com/{}",
    "Twitter": "https://twitter.com/{}",
    "GitHub": "https://github.com/{}",
}

def username_generator(number):

    base = str(number)

    usernames = [
        base,
        base[-6:],
        "user"+base[-4:],
        "official"+base[-4:]
    ]

    return usernames


def social_scan(usernames):

    print("\nScanning Social Media Accounts...\n")

    for username in usernames:

        for site, url in sites.items():

            link = url.format(username)

            try:
                r = requests.get(link, timeout=5)

                if r.status_code == 200:
                    print(f"[FOUND] {site} -> {link}")

            except:
                pass


def trace(number):

    try:

        phone = phonenumbers.parse(number)

        print("\n===== Phone Intelligence Report =====\n")

        print("Valid Number :", phonenumbers.is_valid_number(phone))
        print("Country      :", geocoder.description_for_number(phone,"en"))
        print("Carrier      :", carrier.name_for_number(phone,"en"))

        usernames = username_generator(phone.national_number)

        print("\nGenerated Usernames:", usernames)

        social_scan(usernames)

    except:
        print("Invalid number format")