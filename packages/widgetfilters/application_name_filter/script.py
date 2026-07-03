#Sample code
def query():
    return {
        "query": "select distinct applicationname as applicationname from aggregation_table where applicationname is not null ",
        "parameters": {}
    }