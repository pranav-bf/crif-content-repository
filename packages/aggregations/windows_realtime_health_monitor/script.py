def type() :
    return 'realtime_health_monitor'

def columns() : #column names to be aggregated
    return ['host','provider']

def archive() :
    return 'daily'
    
def uniquekey(message):
    return None
