def query():
    return {
        "query": "SELECT DISTINCT detectiontechnique FROM entityscoring WHERE detectiontechnique IS NOT NULL",
        "parameters": {},
    }