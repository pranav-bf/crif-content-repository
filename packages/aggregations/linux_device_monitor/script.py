def type() :
    return 'linux_realtime_server_monitor'

def columns() : #column names to be aggregated
    return ['host']

def archive() :
    return 'daily'

def uniquekey(message):
  return None