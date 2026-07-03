def parse(log_line):
    
    try:
        values = log_line.strip('"').split(" ")
        return {"values": values}
    except Exception as e:
        return {"error": "Parsing failed: %s" % str(e)}