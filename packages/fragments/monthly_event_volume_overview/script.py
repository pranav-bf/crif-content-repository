from datetime import datetime, timedelta
from collections import defaultdict

def get_time(n):
    def subtract_months(dt, n):
        # Calculate new month and year
        month = dt.month - n
        year = dt.year
        while month <= 0:
            month += 12
            year -= 1
    
        # Return new datetime at the start of that month
        return datetime(year, month, 1, 0, 0, 0)
    
    # Current time
    now = datetime.now()
    
    # Start of current month
    start_of_month = datetime(now.year, now.month, 1, 0, 0, 0)
    
    previous_month = subtract_months(start_of_month, n)
    end_month = subtract_months(start_of_month, n-1) - timedelta(seconds=1)
    # Format
    return {"starttime":previous_month.strftime("%Y-%m-%d %H:%M:%S"),"endtime":end_month.strftime("%Y-%m-%d %H:%M:%S")}
  
# Format: Specifies the format for the data.
def format():
    return "line"

# Query: Specifies the query to retrieve data.
def query():
    parameters = get_time(1)
    parameters["stattype"] = "PUBLISHED"
    parameters["objectids"] = ["6855562af4b113490cb12e58", "68a84be658609e155463eac4", "6852b78bf4b113490cb12cea", "6852d65af4b113490cb12d1a", "685cf5d1f4b113490cb12e8a", "68775dca54295a253fcd4aad"]
    return {
        "query": "SELECT SUM(statcount) AS total_count, CAST(insert_date AS DATE) AS insert_day  from streamx WHERE stattype = :stattype and  objectid IN (:objectids) GROUP BY insert_day ORDER BY insert_day ",
        "parameters": parameters
    }


def render(results):

    print(results)

    
    # Step 1: Build labels and data directly
    labels = [row['insert_day'] for row in results]
    total_event_counts = [
        row.get('total_count', row.get('total_events', 0)) for row in results
    ]
    
    # Step 2: Prepare chart data
    data = [
        {
            "label": "Total Event",
            "data": total_event_counts,
            "borderColor": "#3498db"
        }
    ]


    return {"result": {"labels": labels, "data": data}}