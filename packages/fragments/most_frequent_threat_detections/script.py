# Format: Specifies the format for the data.



def format():
    return "horizontalBar"

# Query: Specifies the query to retrieve data.
def query():
    
    return {
        "query": "select detectionname, count(*) as totalevents from entityscoring group by detectionname",
        "parameters": {},
        "options" : {"sortcol" : "totalevents",  "sortorder" : "desc" , "limit" : 5 , "offset" : 0}
      
    }


def render(results):

    if not results or len(results) == 0:
        raise Exception("no results found")

    labels = []
    data_points = []
    
    for row in results:
      detectionname = row['detectionname']  # u'2025-07-08T15:00:00.000+00:00'
      count =  row['totalevents']

      data_points.append(count)
      labels.append(detectionname)
    
    
    
    # columns = ['entity' , 'senderemailaddress','receiveremailaddress','urloriginal','lastdetectiontime']

    data= [{"label": 'Count',"data": data_points,"backgroundColor":  [
        "#003F5C",
        "#004c6d",
        "#006083",
        "#00cfe3",
        "#88c580",
        "#aed987",
        "#d6ec91",
        "#ffff9d",
        "#fee17e",
        "#00876c",
        "#3d9c73",
        "#63b179",
        "#fcc267",
        "#f7a258",
        "#ef8250",
        "#008bad",
        "#00a1c1",
        "#00b8d3",
        "#e4604e",
        "#d43d51"
      ]}]

    return  {"result":{"labels": labels, "data": data}}