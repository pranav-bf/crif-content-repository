from datetime import datetime


  
def format():
  return "tabular"


def query():
  return {
      'query': 'select distinct on (source_device_name) last_log,total_events,source_device_name from fortigate_device_events where source_device_name is not null and partition_key = :partition_key order by source_device_name, total_events desc',
      'parameters': {"partition_key":"Linux~OS~Security"}
  }


def render(result):
    if not result or len(result) == 0:
        raise Exception("no results found")

    labels = ["LastLog", "Device", "TotalEvents"]
    data = []


    for row in result:
        host = row.get("source_device_name", "")
        if ":" in host:
            continue

        last_activity_time = _format_timestamp(row.get("last_log"))
        total = row.get("total_events", 0)
        formatted_total = _format_number(total)

        
        data.append([last_activity_time, host, formatted_total])
    print("++++++++++++++++++++++++++++++")
    print("result",result)
    print("++++++++++++++++++++++++++++++")

    return {
        "result": {
            "labels": labels,
            "data": data
        }
    }



def _format_number(num):
    try:
        num = float(num)
    except:
        return num

    if num >= 1000000000:
        return "{:.1f}B".format(num / 1000000000.0)
    elif num >= 1000000:
        return "{:.1f}M".format(num / 1000000.0)
    elif num >= 1000:
        return "{:.1f}K".format(num / 1000.0)
    else:
        return int(num)
      
def _format_timestamp(ts):
    try:
        ts = float(ts) / 1000.0   # convert ms → seconds
        dt = datetime.utcfromtimestamp(ts)
        return dt.strftime("%d-%m-%Y %H:%M")
    except:
        return ts