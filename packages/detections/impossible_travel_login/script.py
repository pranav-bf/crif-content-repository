from datetime import datetime

def init(event):
  
    source_lat = event.get("source_latitude")
    source_lon = event.get("source_longitude")
    location_map = {
        "city":  event.get("source_city"),
        "country": event.get("source_country")
    }

  
    print ("source lon", source_lon)
    print ("source lat", source_lat)
    print ("location_map", location_map)

    clusters = stats.speed(source_lat, source_lon,location_map)
    print ("[DEBUG] init(): clusters =", clusters)

    session.set("geospeedviolation", [clusters])
    return "Initialized beaconing detection (MITRE T1071.001)"


# Define aggregation window for scheduled detection (short and recent)
def window():
    return '30m'

# Define how events are grouped for analysis
def groupby():
    return ['user_name']

def investigate():
    return "vpn_use_in_impossible_travel"

def automate():
    return True

# Assign anomaly score to each event
def algorithm(event):
    geospeedviolation_list = session.get("geospeedviolation")
    print("anomalies_list  ", geospeedviolation_list)

    if geospeedviolation_list and isinstance(geospeedviolation_list, list) and len(geospeedviolation_list) > 0:
        geospeedviolation = geospeedviolation_list[0]
        print("[geospeedviolation] algorithm(): clusters =", geospeedviolation)

        if geospeedviolation.get("speedKmh") > 400:
          return 0.75

    return 0.0

# # Not using custom clustering logic here
def clusters(event): 
    return session.get("geospeedviolation")
  
def context(event_data):
    anomalies = session.get("geospeedviolation")[0]


    oldLocationDetails=anomalies.get("oldLocationDetails")
    old_city    = oldLocationDetails.get("city")
    old_country = oldLocationDetails.get("country")
    old_time_ms = anomalies.get("oldTimestamp")

  
    new_time_ms = anomalies.get("newTimestamp")
    newLocationDetails=anomalies.get("newLocationDetails")
    new_city    = newLocationDetails.get("city")
    new_country = newLocationDetails.get("country")
    distance_km = anomalies.get("distanceKm")
    speed_kmh = anomalies.get("speedKmh")

    old_time = datetime.utcfromtimestamp(int(old_time_ms) / 1000).strftime("%d %b %I:%M %p")
    new_time = datetime.utcfromtimestamp(int(new_time_ms) / 1000).strftime("%d %b %I:%M %p")


    return (
        "Impossible travel detected for account %s. Previous login was from %s, %s at %s. "
        "The next login occurred from %s, %s at %s. "
        "This represents a travel distance of %.2f km at an estimated speed of %.2f km/h, "
        "which exceeds realistic human travel limits."
        % (
            event_data.get('user_name'),
            old_city, old_country, old_time,
            new_city, new_country, new_time,
            distance_km, speed_kmh,
        )
    )



# Severity of detection
def criticality():
    return 'HIGH'

  
# MITRE ATT&CK tactic mapping
def tactic():
    return 'Credential Access (TA0006)'

# MITRE ATT&CK technique mapping
def technique():
    return 'Valid Accounts (T1078)'


# Save artifacts like IP, location, and user
def artifacts():
    return stats.collect(['source_ip', 'source_country', 'source_latitude','source_longitude', 'source_city'])

# Define affected entity
def entity(event):
    return {
        'derived': False,
        'value': event.get('user_name'),
        'type': 'Employee'
    }
