# Format: Specifies the format for the data.
def format():
    return "doughnut"

# Query: Specifies the query to retrieve data.
def query():
    
    return {
        "query": "select distinct detectioncriticality as criticality , count(*) as totalevents from entityscoring group by criticality ",
        "parameters": {}
    }


def render(results):

    if not results or len(results) == 0:
        raise Exception("no results found")

    labels = []
    data_points =[]
    colors = []
    criticality_colors = {
        "LOW": "#098b39",
        "MEDIUM": "#f5c304",
        "HIGH": "#ff5e5e",
        "CRITICAL": "#d94040"
    }

    for item in results:
      criticality = item['criticality']  # u'2025-07-08T15:00:00.000+00:00'
      count = item['totalevents']

      data_points.append(count)
      labels.append(criticality)
      colors.append(criticality_colors.get(criticality, "#95a5a6"))
    
    dataset= [{"data": data_points,"backgroundColor": colors}]

    return  {"result":{"labels": labels, "data": dataset}}
