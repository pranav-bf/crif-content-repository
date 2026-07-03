import time
import re
from collections import defaultdict

def configure():
    """
    Returns default configuration of the widget.

    Returns:
        dict: Widget layout, filters, type, and search options.
    """
    return {
        "searchable": False,
        "datepicker": False,
        "properties": {"type": "table", "layout": "default"},
        "filters": [],
        "dimension": {"x": 0, "y": 0, "width": 4, "height": 7},
        "icon":"Fortigate",
        "descriptionvisible":True
    }

def query():
        return {
        'query': 'select distinct on (source_device_name) last_log,total_events,source_device_name from device_event_edge where source_device_name is not null and partition_key = :partition_key order by source_device_name, total_events desc',
        'parameters': {"partition_key":"Fortinet~FortiGate~Firewall"}
    }




    # this to return filter queries based on filters selected by user and its parameters

def filters(filters):
        return None


    # this to return free text search query and its parameters

def search(freetext):
        return None


    # this to return sort query

def sort():
    """
    Sorting logic for the results.

    Returns:
        dict or None: Sorting preferences or None if not applicable.
    """
    return {
        "column": "",
        "order": "asc"
    }

def render(results):

    currTime = round(time.time()*1000)
    print(results)
    finalResult = map(
        lambda entry: process_entry(
            (normalize_host(entry["source_device_name"]), {
                "last_log": entry.get("last_log", 0),
                "total_events": entry.get("total_events", 0)
            }),
            currTime
        ),
        results
    )

    columns = ["device", "events"]

    return {"result": {"rows": list(finalResult), "columns": columns}}

def normalize_host(host):
    """Remove surrounding quotes if present and ensure consistency."""
    return re.sub(r'^["\']+|["\']+$', '', host)
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
        
        
def process_entry(item, currTime):
    host, data = item
    timediff = currTime - data["last_log"]

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