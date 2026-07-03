def window():
    return '1d'

def groupby():
    return ['host']

def automate():
    return False

def _check_tool(img, cmd):
# Check if lateral movement tool is present
    lateral_tools = ['psexec.exe', 'wmic.exe', 'powershell.exe', 'mstsc.exe', 'services.exe', 'svchost.exe', 'wsmprovhost.exe']
    lateral_cmds = ['psexec', 'wmic /node:', 'powershell remoting', 'new-pssession', 'invoke-command', 'net use', 'net session', 'net share', 'admin$', '\\c$', 'rdesktop', 'remote desktop', 'tasklist /s', 'schtasks /create /s', 'sc.exe', 'service install', 'dcom', 'wmi']
    
    tool_found = img in lateral_tools
    cmd_found = False
    for keyword in lateral_cmds:
        if keyword in cmd:
            cmd_found = True
            break
    return tool_found or cmd_found

def _check_port(cmd, dst):
 # Check if suspicious ports are used
    rdp_ports = ['3389', '3388']
    smb_ports = ['445', '139']
    all_ports = rdp_ports + smb_ports
    
    port_in_cmd = False
    for p in all_ports:
        if p in cmd:
            port_in_cmd = True
            break
    
    port_in_dst = False
    if dst:
        for p in all_ports:
            if dst.endswith(p):
                port_in_dst = True
                break
    
    return port_in_cmd or port_in_dst

def _check_parent(parent):
  # Check if parent process is suspicious
    sus_parents = ('wscript.exe', 'cscript.exe', 'powershell.exe', 'winword.exe')
    return parent.endswith(sus_parents)

def _check_event(evt):
  # Check if event ID indicates lateral movement
    service_events = ['4624', '5140', '4672', '7045', '4688', '4720', '4732', '4756']
    return evt in service_events

def algorithm(event):
    img = (event.get('source_process_name') or '').lower()
    cmd = (event.get('command_line') or '').lower()
    evt = event.get('event_id') or ''
    src = event.get('source_ip') or ''
    dst = event.get('destination_ip') or ''
    parent = (event.get('parent_process_name') or '').lower()

    is_tool = _check_tool(img, cmd)
    is_port = _check_port(cmd, dst)
    is_parent = _check_parent(parent)
    service_protocol = _check_event(evt)

    if is_tool or is_port or is_parent or service_protocol:
        stats.count('lateral_movement')
        c = stats.getcount('lateral_movement')
        if c >= 2:
            return 1.0
        if c == 1:
            return 0.75
    return 0.0

def context(event):
    proc = event.get('process_name') or 'Unknown'
    cmd = event.get('command_line') or 'N/A'
    src = event.get('src_ip') or 'Unknown'
    dst = event.get('dest_ip') or 'Unknown'
    par = event.get('parent_process_name') or 'Unknown'
    
    return (
        "A suspected lateral movement activity has been detected. "
        "Process '{0}' spawned by '{1}' executed command: '{2}'. "
        "Connection from {3} to {4}. "
        "This is categorized under Lateral Movement (TA0008). "
        "Investigate immediately to verify if this is legitimate administrative activity."
    ).format(proc, par, cmd, src, dst)

def criticality():
    c = stats.getcount('lateral_movement')
    if c >= 2:
        return 'CRITICAL'
    elif c == 1:
        return 'HIGH'
    return None

def tactic():
    return 'Lateral Movement (TA0008)'

def technique():
    return 'Remote Services (T1021)'

def artifacts():
    return ['host', 'source_process_name', 'command_line', 'parent_process_name', 'source_ip', 'destination_ip', 'event_id']

def entity(event):
    return {'derived': False, 'value': event.get('host'), 'type': 'device'}
