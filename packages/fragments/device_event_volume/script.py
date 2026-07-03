from datetime import datetime


  
def format():
  return "tabular"


def query():
    # TODO: Define your SQL query and parameters for the widget.
    return [{
        'query': 'SELECT host, MAX(last_log) AS last_log,SUM(total_events) AS total_events ,jumpserver FROM device_event_core WHERE host IS NOT NULL AND partition_key = :partition_key GROUP BY host,jumpserver  ORDER BY total_events desc',
        'parameters': {"partition_key":"Microsoft~Windows~Audit"}
    },{
        'query': 'SELECT source_device_name as host, MAX(last_log) AS last_log,SUM(total_events) AS total_events ,jumpserver FROM device_event_edge WHERE source_device_name IS NOT NULL AND partition_key = :partition_key GROUP BY source_device_name,jumpserver  ORDER BY total_events desc',
        'parameters': {"partition_key":"Fortinet~FortiGate~Firewall"}
    },{
        'query': 'SELECT source_device_name as host, MAX(last_log) AS last_log,SUM(total_events) AS total_events ,jumpserver FROM device_event_edge WHERE source_device_name IS NOT NULL AND partition_key = :partition_key GROUP BY source_device_name,jumpserver  ORDER BY total_events desc',
       'parameters': {"partition_key":"Linux~OS~Security"}
    },{
        'query': 'SELECT host, MAX(last_log) AS last_log,SUM(total_events) AS total_events ,jumpserver FROM device_event_core WHERE host IS NOT NULL AND partition_key = :partition_key GROUP BY host,jumpserver  ORDER BY total_events desc',
        'parameters': {"partition_key":"Palo Alto~Network~Firewall"}
    },{
        'query': 'SELECT source_device_name as host, MAX(last_log) AS last_log,SUM(total_events) AS total_events ,jumpserver FROM device_event_edge WHERE source_device_name IS NOT NULL AND partition_key = :partition_key GROUP BY source_device_name,jumpserver  ORDER BY total_events desc',
       'parameters': {"partition_key":"Radware~Network~Security"}
    }]


def render(result):
    windows_result = result[0]
    fortigate_result = result[1]
    linux_result = result[2]
    palo_alto_result = result[3]
    radware_result = result[4]
    
    # Windows Devices
    for row in windows_result:
        host = row.get("host")
        server = row.get("jumpserver")
        ip_result = tpi.query("HostnameWithIps", "Hostname = ?", [host])
        ip_result_rows = ip_result.get("rows")
        row["source"] = "Windows"
        

        if ip_result_rows:
            row["ip"] = ip_result_rows[0][1]

    # Fortigate Devices
    for row in fortigate_result:
        host = row.get("host")
        server = row.get("jumpserver")
        ip_result = tpi.query("HostnameWithIps", "Hostname = ?", [host])
        ip_result_rows = ip_result.get("rows")
        row["source"] = "Fortigate"

        if ip_result_rows:
            row["ip"] = ip_result_rows[0][1]

    # Linux Devices
    for row in linux_result:
        host = row.get("host")
        server = row.get("jumpserver")
        ip_result = tpi.query("HostnameWithIps", "Hostname = ?", [host])
        ip_result_rows = ip_result.get("rows")
        row["source"] = "Linux"

        if ip_result_rows:
            row["ip"] = ip_result_rows[0][1]

    # Palo Alto Devices
    for row in palo_alto_result:
        host = row.get("host")
        server = row.get("jumpserver")
        ip_result = tpi.query("HostnameWithIps", "Hostname = ?", [host])
        ip_result_rows = ip_result.get("rows")
        row["source"] = "Palo Alto"

        if ip_result_rows:
            row["ip"] = ip_result_rows[0][1]

    # Radware Devices
    for row in radware_result:
        host = row.get("host")
        server = row.get("jumpserver")
        ip_result = tpi.query("HostnameWithIps", "Hostname = ?", [host])
        ip_result_rows = ip_result.get("rows")
        row["source"] = "Radware"

        if ip_result_rows:
            row["ip"] = ip_result_rows[0][1]
          
    today = datetime.now()
    formatted_date = "{} {}".format(today.day, today.strftime("%b"))
    labels = ["LastLog", "Device", "Events({})".format(formatted_date), "IPAddress", "Source", "JumpServer"]  
    # Option 2: Using extend()
    data = []
    data.extend(windows_result)
    data.extend(fortigate_result)
    data.extend(linux_result)
    data.extend(palo_alto_result)
    data.extend(radware_result)

    
    newdata = []
    for row in data:
      host = row.get("host", "")
      ip = row.get("ip", "")
      source = row.get("source", "")
      server = row.get("jumpserver", "")
  
      last_activity_time = _format_timestamp(row.get("last_log"))
      total = row.get("total_events", 0)
      formatted_total = _format_number(total)
  
      
      newdata.append([last_activity_time, host, formatted_total,ip,source,server])


    return {
        "result": {
            "labels": labels,
            "data": newdata
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
        ts = int(str(ts)) / 1000.0
        dt = datetime.utcfromtimestamp(ts)
        return dt.strftime("%d-%m-%Y %H:%M")
    except Exception as e:
        print("Timestamp error:", ts, e)
        return ts
      