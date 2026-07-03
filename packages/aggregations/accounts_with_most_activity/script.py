def type() :
    return 'account_detection_map'

def columns() : #column names to be aggregated
    return ['source_device_name']

def archive() :
    return 'daily'

def uniquekey(message):
  return None

  
  