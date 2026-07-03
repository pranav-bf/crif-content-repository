def window():
    return None

def groupby():
    return None

def algorithm(event):
    command = (event.get('process_command') or '').lower()
    dest_ip = event.get('destination_ip')

    exfil_tools = ['scp','rsync','curl','wget']

    if any(tool in command for tool in exfil_tools) and dest_ip:

        if dest_ip.startswith('10.') or dest_ip.startswith('192.168.') or dest_ip.startswith('172.'):
            return 0.0

        return 0.75

    return 0.0



def context(event_data):
    return (
        "Potential data exfiltration detected on host " + str(event_data.get('host')) +
        ". Process " + str(event_data.get('process_name')) +
        " initiated transfer to external destination " + str(event_data.get('destination_ip')) + " with command " + str(event_data.get('process_command')) +
        "."
    )


def criticality():
    return 'HIGH'


def tactic():
    return 'Exfiltration (TA0010)'


def technique():
    return 'Exfiltration Over Alternative Protocol (T1048)'

def artifacts():
    return stats.collect(['host','process_name','destination_ip', 'process_command', 'executable', 'file_path', 'event_details'])


def entity(event):
    return {'derived': False, 'value': event.get('host'), 'type': 'host'}