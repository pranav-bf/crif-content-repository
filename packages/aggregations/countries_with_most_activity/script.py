def type() :
    return 'country_activity_map'

def columns() : #column names to be aggregated
    return ['destination_country']
  
def archive() :
    return 'daily'
  
def uniquekey(message):
  return None