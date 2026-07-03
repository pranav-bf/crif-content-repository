def query():
    return {
        "query": "SELECT DISTINCT detectiontactic FROM entityscoring WHERE detectiontactic IS NOT NULL",
        "parameters": {},
    }