def type() :
    return 'source_destination_data_transfer'
  

def columns() : #column names to be aggregated
    return ["network_bytes_transferred","destination_ip","source_ip"]

def archive() :
    return 'daily'
  

def uniquekey(message):
  return None