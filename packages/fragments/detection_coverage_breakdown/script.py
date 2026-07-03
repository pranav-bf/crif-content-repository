# Format: Specifies the format for the data.
def format():
    return "pie"

# Query: Specifies the query to retrieve data.
def query():
    
    return {
        "query": "SELECT detectiontactic AS tactic,  COUNT(idx) AS totalevents FROM entityscoring WHERE detectiontactic IS NOT NULL GROUP BY tactic",
        "parameters": {}
    }


def render(results):

    if not results or len(results) == 0:
        raise Exception("no results found")

      
    labels = []
    data_points =[]

    for item in results:
      tactic = item['tactic']  # u'2025-07-08T15:00:00.000+00:00'
      count = item['totalevents']

      data_points.append(count)
      labels.append(tactic)
    
    
    # columns = ['entity' , 'senderemailaddress','receiveremailaddress','urloriginal','lastdetectiontime']
    if len(labels) > 5:
        background_colors = ["#63b179", "#d6ec91", "#ffff9d", "#fee17e"]
    else:
        background_colors = [
            "#003F5C", "#004c6d", "#006083", "#00cfe3", "#88c580",
            "#aed987", "#d6ec91", "#ffff9d", "#fee17e", "#00876c",
            "#3d9c73", "#63b179", "#fcc267", "#f7a258", "#ef8250",
            "#008bad", "#00a1c1", "#00b8d3", "#e4604e", "#d43d51"
        ]
      
    show_legend = len(data_points) > 0

    options = {
        "plugins": {
            "datalabels": {
                "formatter": "showRawData"
            },
          "legend": {
                "display": show_legend
            }
        }
    }

    dataset= [{"data": data_points,"backgroundColor": background_colors[:len(data_points)]}]

    return  {"result":{"labels": labels, "data": dataset, "options": options}}
