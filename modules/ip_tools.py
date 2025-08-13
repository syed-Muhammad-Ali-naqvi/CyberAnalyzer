# ip_geolocation.py
import requests

def get_ip_geolocation(ip):
    url = f"http://ip-api.com/json/{ip}?fields=status,message,query,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting"
    response = requests.get(url)
    data = response.json()

    if data.get("status") != "success":
        raise ValueError(f"Error: {data.get('message', 'Unknown error')}")

    return {
        "IP Address": data.get("query"),
        "Country": f"{data.get('country')} ({data.get('countryCode')})",
        "Region": f"{data.get('regionName')} ({data.get('region')})",
        "City": data.get("city"),
        "ZIP Code": data.get("zip"),
        "Latitude": data.get("lat"),
        "Longitude": data.get("lon"),
        "Timezone": data.get("timezone"),
        "ISP": data.get("isp"),
        "Organization": data.get("org"),
        "ASN": data.get("as"),
        "Mobile Network": "Yes" if data.get("mobile") else "No",
        "Using Proxy": "Yes" if data.get("proxy") else "No",
        "Hosting Provider": "Yes" if data.get("hosting") else "No",
        "Map Link": f"https://www.google.com/maps/search/?api=1&query={data.get('lat')},{data.get('lon')}"
    }
