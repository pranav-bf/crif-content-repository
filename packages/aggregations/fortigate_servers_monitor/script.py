def type() :
    return 'fortigate_realtime_server_monitor'

def columns() : #column names to be aggregated
    return ['source_device_name']

def archive() :
    return 'daily'

def uniquekey(message):
  return None