import instaloader
import getpass
import threading
import time
from instaloader.exceptions import TwoFactorAuthRequiredException

def input_with_timeout(prompt, timeout=60):
    user_input = [None]

    def get_input():
        user_input[0] = getpass.getpass(prompt)

    t = threading.Thread(target=get_input)
    t.start()
    t.join(timeout)

    if t.is_alive():
        print("\n⏰ Time expired (60 seconds). Login cancelled.")
        return None

    return user_input[0]


def osint(username):

    try:

        L = instaloader.Instaloader()

        USER = input("Enter Instagram Username: ")
        PASS = getpass.getpass("Enter Instagram Password: ")

        try:
            L.login(USER, PASS)

        except TwoFactorAuthRequiredException:

            print("\n🔐 2FA verification required")

            otp = input_with_timeout("Enter OTP Code (60s): ", 60)

            if otp is None:
                return

            L.two_factor_login(otp)

        profile = instaloader.Profile.from_username(L.context, username)

        print("\n========== INSTAGRAM OSINT ==========\n")

        print("Username        :", profile.username)
        print("Full Name       :", profile.full_name)
        print("User ID         :", profile.userid)
        print("Bio             :", profile.biography)
        print("Followers       :", profile.followers)
        print("Following       :", profile.followees)
        print("Posts           :", profile.mediacount)
        print("Private Account :", profile.is_private)
        print("Verified        :", profile.is_verified)
        print("Business Acc    :", profile.is_business_account)
        print("External URL    :", profile.external_url)
        print("Profile Pic URL :", profile.profile_pic_url)

        print("\n=====================================\n")

    except Exception as e:
        print("Error:", e)