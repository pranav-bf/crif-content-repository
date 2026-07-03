def type() :
    return 'event_level_check'

def columns() : #column names to be aggregated
    return ['event_level']

def archive() :
    return 'daily'

def uniquekey(message):
    return None