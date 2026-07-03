def type() :
    return 'apps_detection_map'

def columns() : #column names to be aggregated
    return ['applicationname']

def archive() :
    return 'daily'

def uniquekey(message):
  return None