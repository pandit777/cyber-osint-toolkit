from modules import ip_tracker, port_scanner, whois_lookup, subdomain_finder, email_harvester, mobile_trace, instagram_osint, phone_intel

def menu():
    print("""
    ===== Cyber Security Toolkit =====

██████╗ ██╗      █████╗  ██████╗██╗  ██╗    ██╗  ██╗ █████╗ ████████╗
██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝    ██║  ██║██╔══██╗╚══██╔══╝
██████╔╝██║     ███████║██║     █████╔╝     ███████║███████║   ██║   
██╔══██╗██║     ██╔══██║██║     ██╔═██╗     ██╔══██║██╔══██║   ██║   
██████╔╝███████╗██║  ██║╚██████╗██║  ██╗    ██║  ██║██║  ██║   ██║   
╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝    ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   

         ██╗  ██╗ █████╗  ██████╗██╗  ██╗███████╗██████╗ 
         ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗
         ███████║███████║██║     █████╔╝ █████╗  ██████╔╝
         ██╔══██║██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
         ██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║
         ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
         Hacking             with                  Gourav

    1. IP Tracker
    2. Port Scanner
    3. Whois Lookup
    4. Subdomain Finder
    5. Email Harvester
    6. Mobile Number Trace
    7. Instagram Osint
    0. Exit
    """)

while True:
    menu()
    choice = input("Select Option: ")

    if choice == "1":
        ip = input("Enter IP: ")
        ip_tracker.track(ip)

    elif choice == "2":
        host = input("Enter Host: ")
        port_scanner.scan(host)

    elif choice == "3":
        domain = input("Enter Domain: ")
        whois_lookup.lookup(domain)

    elif choice == "4":
        domain = input("Enter Domain: ")
        subdomain_finder.find(domain)

    elif choice == "5":
        domain = input("Enter Website URL: ")
        email_harvester.harvest(domain)

    elif choice == "6":
        number = input("Enter Mobile Number with country code: ")
        mobile_trace.trace(number)

    elif choice == "7":
        username = input("Enter Instagram Username: ")
        instagram_osint.osint(username)

    elif choice == "0":
        break
