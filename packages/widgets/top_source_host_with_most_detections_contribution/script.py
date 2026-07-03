# sample name -> widgets/accounts_compromised/script.py

# this to return default widget config
def configure():
    return {
        "searchable": False,
        "datepicker": True,
        "pagination": False,
        "properties": {"type": "bar","onclick":"open_offcanvaspanel"},
        "dimension": {"x":0,"y":0,"width": 4, "height": 3}
    }

# this to return query to be used for rendering widget and its parameters
def query():
    return {
        'query': "SELECT source_hostname  as hostname, count(*) as total from aggregation_table where source_hostname is not null and type = :type group by source_hostname",
        'parameters': {"type":"host_detection_map"}
    }


# this to return filter queries based on filters selected by user and its parameters
def filters(filter):
    return None


# this to return free text search query and its parameters
def search(freetext):
    return None


# this to return sort query
def sort():
    return{
        "sortcol":"total",
        "sortorder":"desc"    
    }

def render(result):
    data = []
    categories = []
    counter=0

    for item in result:
        if(counter<10):
            categories.append(item["hostname"])
            data.append(item["total"])
            counter=counter+1
        
    return {"result":{"series":[{'data':data}], 'categories': categories,"column":"source_hostname","label":"Hostname","type":"host_detection_map","uniquekey":["category"],"columnmap":["source_hostname"]}}
