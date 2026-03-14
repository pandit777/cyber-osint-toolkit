import whois

def lookup(domain):
    w = whois.whois(domain)

    print("Domain:", w.domain_name)
    print("Registrar:", w.registrar)
    print("Creation Date:", w.creation_date)
    print("Expiration Date:", w.expiration_date)