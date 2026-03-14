import requests

def track(ip):
    url = f"http://ip-api.com/json/{ip}"
    
    try:
        response = requests.get(url)
        data = response.json()

        print("IP:", data.get('query', 'Not Found'))
        print("Country:", data.get('country', 'Not Found'))
        print("Region:", data.get('regionName', 'Not Found'))
        print("City:", data.get('city', 'Not Found'))
        print("ISP:", data.get('isp', 'Not Found'))
        print("Latitude:", data.get('lat', 'Not Found'))
        print("Longitude:", data.get('lon', 'Not Found'))

    except Exception as e:
        print("Error:", e)