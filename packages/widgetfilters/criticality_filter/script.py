
def query():
    return {
        "query": "SELECT DISTINCT detectioncriticality FROM entityscoring WHERE detectioncriticality IS NOT NULL",
        "parameters": {},
    }