import re
# this to return default widget config
def configure():
    return {
        "searchable": False, #Boolean value depending whether the widget is searchable or not
        "datepicker": False,
        "properties": {"type": "pie","onclick":"open_offcanvaspanel"},
        "dimension": {"x": 9, "y": 0, "width": 3, "height": 3} #dimensions of widget on GRID
    }
  

# this to return query to be used for rendering widget and its parameters
def query():
    return {
        "query": "select event_severity,count(*) as total_events from aggregation_table where type = :type group by event_severity",
        "parameters": {"type":"realtime_health_monitor"},
    }
# this to return filter queries based on filters selected by user and its parameters
def filters(filters):
    return None

# this to return free text search query and its parameters
def search(freetext):
    return None

# this to return sort query
def sort():
    return{
        "sortcol":"total_events",
        "sortorder":"desc"    
    }


def render(result):
    transformed_data = []
    data = {}
    for item in result:
        data[remove_quotes(item["event_severity"])] = item["total_events"]

    for level in data.keys():
        transformed_data.append({
            "name": level,
            "y": data[level]
        })
    
    return {"result":transformed_data,"column":"event_severity","label":"Event Severity","type":"realtime_health_monitor","uniquekey":["name"],"columnmap":["event_level"]}

def remove_quotes(host):
    """Remove surrounding quotes if present and ensure consistency."""
    return re.sub(r'^["\']+|["\']+$', '', host)