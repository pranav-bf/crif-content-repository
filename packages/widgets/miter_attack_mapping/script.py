

def configure():
    return {
        "searchable": False, #Boolean value depending whether the widget is searchable or not
        "datepicker": False,
        "properties": {"type": "threatcoverage_mitre"},
        "dimension": {"x": 0, "y": 1, "width": 12, "height": 6} #dimensions of widget on GRID
    }

# this to return query to be used for rendering widget and its parameters
def query():

    return {
        "query": "select * from implicit_algorithm",
        "parameters": {}
    }
def algorithm():
    starttime = parameters.get("starttime")
    endtime = parameters.get("endtime")
    timephrase = parameters.get("timePhrase")
  
    return threatCoverage.getMappingWithTimeStamp(starttime,endtime,timephrase)

# this to return filter queries based on filters selected by user and its parameters
def filters(filters):
    return None
# this to return free text search query and its parameters
def search(freetext):
    return None

# this to return sort query
def sort():
    return None




def update_occurrence_times(categorized_occurrences, category, first_occurrence, latest_occurrence):
    """
    Helper function to update occurrence times for a category.
    """
    if categorized_occurrences[category]["first_occurrence"] is None or first_occurrence < categorized_occurrences[category]["first_occurrence"]:
        categorized_occurrences[category]["first_occurrence"] = first_occurrence
    if categorized_occurrences[category]["latest_occurrence"] is None or latest_occurrence > categorized_occurrences[category]["latest_occurrence"]:
        categorized_occurrences[category]["latest_occurrence"] = latest_occurrence

def render(data):
    if not data:
        raise Exception("No results found")
    
    result = data[0]  # Accessing the first element of the "result" list

    if not result or "mapping" not in result or not result["mapping"]:
        raise Exception("Mapping data is missing or invalid")

    # Mapping of tactics to categories
    category_mapping = {
        "Reconnaissance": ["Reconnaissance", "Resource Development", "Initial Access", "Execution"],
        "Delivery": ["Persistence", "Privilege Escalation"],
        "Exploit": ["Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection"],
        "Command and Control": ["Command and Control", "Exfiltration"],
        "Impact": ["Impact"]
    }

    # Initialize categorized result and occurrences
    categorized_result = {
        "Reconnaissance": [],
        "Delivery": [],
        "Exploit": [],
        "Command and Control": [],
        "Impact": []
    }

    categorized_occurrences = {
        "Reconnaissance": {"first_occurrence": None, "latest_occurrence": None},
        "Delivery": {"first_occurrence": None, "latest_occurrence": None},
        "Exploit": {"first_occurrence": None, "latest_occurrence": None},
        "Command and Control": {"first_occurrence": None, "latest_occurrence": None},
        "Impact": {"first_occurrence": None, "latest_occurrence": None}
    }

    # Process mapping data
    for detection in result["mapping"]:
        tactic = detection["detectiontactic"].split(" (")[0]  # Extracting tactic name
        for category, tactics in category_mapping.items():
            if tactic in tactics:
                categorized_result[category].append(detection)

    # Process occurrence data
    for occurrence in result.get("occurrence", []):
        tactic = occurrence["detectiontactic"].split(" (")[0]  # Extracting tactic name
        for category, tactics in category_mapping.items():
            if tactic in tactics:
                first_occurrence = occurrence["first_occurrence"]
                latest_occurrence = occurrence["latest_occurrence"]
                update_occurrence_times(categorized_occurrences, category, first_occurrence, latest_occurrence)

    return {"result": {"data": categorized_result, "occurrence": categorized_occurrences}}