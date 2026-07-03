def type() :
    return 'hostname_entity_map'

def columns() : #column names to be aggregated
    return ['source_ip' , 'source_device_name']

def archive() :
    return 'daily'

def uniquekey(message):
  return None