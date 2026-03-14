import phonenumbers
from phonenumbers import geocoder, carrier, timezone

def trace(number):

    try:

        phone = phonenumbers.parse(number)

        print("\nMobile Number Info\n")

        print("Valid Number:", phonenumbers.is_valid_number(phone))
        print("Country:", geocoder.description_for_number(phone, "en"))
        print("Operator:", carrier.name_for_number(phone, "en"))
        print("Timezone:", timezone.time_zones_for_number(phone))

    except:
        print("Invalid number format")