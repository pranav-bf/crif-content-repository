


def transform(event):
    source_ip = event.get("source_ip")

    if not isinstance(source_ip, basestring) or source_ip.strip() in ["", "-", "UNKNOWN", "::1"]:
        print("not instance"+source_ip)
        return event
    ip_int = ip_to_int(source_ip)
  
    locationObject = tpi.query("Maxmindipv4city", "? >= start_ip and ? <= end_ip", [ip_int,ip_int])
    rows = locationObject.get("rows", [])

    if not rows:
        print("No location found for IP:", source_ip)
        return event
  
    index = locationObject.get("columns").index("geoname_id")
    geoname_id = locationObject.get("rows")[0][index]
  
    countryObject = tpi.query("Maxmindcountries", "geoname_id=?", [geoname_id])
    
    index = countryObject.get("columns").index('country_name')
    event["source_location"] = countryObject.get("rows")[0][index]
    print(event["source_location"])
    return event;


def ip_to_int(ip_str):
    a, b, c, d = map(int, ip_str.split('.'))
    return (a << 24) + (b << 16) + (c << 8) + d