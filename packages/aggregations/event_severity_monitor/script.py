def type() :
    return 'event_level_host'

def columns() : #column names to be aggregated
    return ['source_country','event_level', 'event_details']

def archive() :
    return 'daily'

def uniquekey(message):
  return None