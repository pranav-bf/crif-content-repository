import time
import re
from collections import defaultdict


# this to return default widget config
def configure():
    return {
        "searchable": False,
      "datepicker": False,
      "properties": {"type": "table"},
        "dimension": {"x":4,"y":7,"width": 4, "height": 7},
       "icon":"Cisco"
    }

# this to return query to be used for rendering widget and its parameters
def query():
    return {
        'query': 'select max(timestamp) as last_activity_time, count(*) as total_events, event_interface  from aggregation_table  where event_interface is not null and type = :type group by event_interface',
        'parameters': {"type":"cisco_switch_realtime_monitor"}
    }



# this to return filter queries based on filters selected by user and its parameters
def filters(filter):
    return None


# this to return free text search query and its parameters
def search(freetext):
    return None


# this to return sort query
def sort():
    return None

def render(results):
    
    currTime = round(time.time()*1000)

    merged_data = defaultdict(lambda: {"last_activity_time": 0, "total_events": 0,"provider": None})

    for entry in results:
        host = normalize_host(entry["event_interface"])
        data = merged_data[host]  # Avoid multiple dictionary lookups

        data["total_events"] += entry.get('total_events',0)
        data["last_activity_time"] = max(data["last_activity_time"], entry.get('last_activity_time',0))

    finalResult = map(lambda result: process_entry(result, currTime), merged_data.iteritems())  
  
    columns = ["device", "events"]


    return  {"result":{"rows":list(finalResult),"columns":columns}}

def normalize_host(host):
    """Remove surrounding quotes if present and ensure consistency."""
    return re.sub(r'^["\']+|["\']+$', '', host)

def process_entry(item, currTime):
    host, data = item
    timediff = currTime - data["last_activity_time"]

    return {
        "events": format_number(data["total_events"]),
        "description": getTimePhrase(timediff),
        "device": host,
        "type":"device",
      "color": (
          "#1debba" if timediff < 3600000 else 
            "#FFA500" if timediff < 21600000 else 
          "#F33D3D"
      ),
    }

def getTimePhrase(timediff):
    seconds = int(timediff // 1000)
    minutes = int(seconds // 60)
    hours = int(minutes // 60)
    days = int(hours // 24)

    if minutes < 1:
        return "{} sec ago".format(seconds)
    elif hours < 1:
        return "{} min ago".format(minutes)
    elif days < 1:
        remaining_minutes = minutes % 60
        return "{} hr {} min ago".format(hours, remaining_minutes) if remaining_minutes else "{} hr ago".format(hours)
    else:
        remaining_hours = hours % 24
        return "{} days {} hr ago".format(days, remaining_hours) if remaining_hours else "{} days ago".format(days)


def format_number(num):
    if num >= 1000000000000:  # Trillions (T)
        return "%.2f T" % (num / 1000000000000.0)
    elif num >= 1000000000:  # Billions (B)
        return "%.2f B" % (num / 1000000000.0)
    elif num >= 1000000:  # Millions (M)
        return "%.2f M" % (num / 1000000.0)
    elif num >= 1000:  # Thousands (K)
        return "%.2f K" % (num / 1000.0)
    else:
        return str(num)  # No formatting for small numbers can u tell me wt is output of render function
        
        