def type() :
    return 'entity_app_frequency_map'

def columns() : #column names to be aggregated
    return ['source_ip' , 'applicationname']

def archive() :
    return 'daily'

  
def uniquekey(message):
  return None
  