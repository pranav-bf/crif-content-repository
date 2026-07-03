
  
def format():
  return "slacompliancecard"


def query():
    # TODO: Define your SQL query and parameters for the widget.
    return {
        "query": """
            SELECT 
                COUNT(*) AS total,

                COUNT(*) FILTER (
                    WHERE responseslastatus = :complied
                ) AS responseSlaComplied,

                COUNT(*) FILTER (
                    WHERE responseslastatus = :breached
                ) AS responseSlaBreached,

                COUNT(*) FILTER (
                    WHERE resolutionslastatus = :complied
                ) AS resolutionSlaComplied,

                COUNT(*) FILTER (
                    WHERE resolutionslastatus = :breached
                ) AS resolutionSlaBreached

            FROM incidentdetails
        """,
        "parameters": {"complied": "COMPLIED","breached": "BREACHED"}
    }


def render(result):
    print("=========================")
    print("slaresult",result)
    
    # extract first row
    row = result[0]

    data = {
        "responseSlaBreached": row["responseSlaBreached"],
        "resolutionSlaComplied": row["resolutionSlaComplied"],
        "responseSlaComplied": row["responseSlaComplied"],
        "resolutionSlaBreached": row["resolutionSlaBreached"]
    }


    return {
        "result": {
            "labels": ["SLA Performance"],      # TITLE of card
            "data": [
                {
                    "r1label": "Response",
                    "r2label": "Resolution",
                    "c1label": "Complied",
                    "c2label": "Breached",
                    "data": [data]
                }
            ]
        }
    }

