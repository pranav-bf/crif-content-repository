def type() :
    return 'entity_bandwidth_map'

def columns() : #column names to be aggregated
    return ['source_ip' , 'network_bytes_transferred']

def archive() :
    return 'daily'
  
def uniquekey(message):
  return None
  