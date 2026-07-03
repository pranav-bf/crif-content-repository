# this to return default widget config
def configure():
    return {
        "searchable": False, #Boolean value depending whether the widget is searchable or not
        "datepicker": False,
        "properties": {"type": "fatalwidget","layout": "conciselayout"},
        "dimension": {"x": 0, "y": 5, "width": 12, "height": 3} #dimensions of widget on GRID
    }

# this to return query to be used for rendering widget and its parameters
def query():
    return {
        "query": """
            SELECT 
                insert_date AS insert_date,
                streamprovider AS provider,
                technique AS technique,
                tactic AS tactic,
                context AS alerts,
                criticality AS criticality
            FROM 
                detection
            WHERE 
                insert_date IS NOT NULL
                AND streamprovider IS NOT NULL
                AND technique IS NOT NULL
                AND tactic IS NOT NULL
                AND context IS NOT NULL
                AND criticality IS NOT NULL
            GROUP BY 
                insert_date, streamprovider, technique, tactic, context, criticality, source_ip
            LIMIT 10
        """,
        "parameters": {},
    }



# this to return filter queries based on filters selected by user and its parameters
def filters(filters):
    return None

# this to return free text search query and its parameters
def search(freetext):
    return None

# this to return sort query
def sort():
    return None


# this to return return formated results to render a widget
def render(results):
    if len(results) > 10:
        results = results[:10]  # Limit to the first five records        
    for result in results:
        result['time']=result['insert_date']
    columnList=['time', 'provider', 'technique', 'tactic','alerts', 'criticality'];
    
    return {"result": results,"columns":columnList}