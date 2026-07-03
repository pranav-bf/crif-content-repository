def window():
    return '1d'

def groupby():
    return ['host']

def automate():
    return False


def algorithm(event):
    img = (event.get('process_name') or '').lower()
    cmd = (event.get('command_line') or '').lower()
    srcip = event.get('source_ip') or ''
    destip = event.get('destination_ip') or ''
    dport = event.get('destination_port') or ''
    parent = (event.get('parent_process_name') or '').lower()
    user = (event.get('source_account_name') or '').lower()

    whitelist_processes = ['authorized_scanner.exe', 'nessus.exe', 'qualys.exe', 'vulnerability_scanner.exe']
    whitelist_users = ['svc_scanner', 'monitoring_agent', 'security_scanner', 'nessus_service']
    
    if img in whitelist_processes or user in whitelist_users:
        return 0.0

    scan_tools = ['nmap.exe', 'angryip.exe', 'masscan.exe', 'netscan.exe', 'advancedip.exe', 'powershell.exe']
    scan_cmds = ['nmap', 'scan', 'masscan', 'portscan', '/16', '/24', '/23', '-p-', 'get-wmiobject win32_tcpipprinterport', 'get-nettcpconnection', 'test-netconnection', 'get-wmiobject win32_service']
    
    tool_found = img in scan_tools
    cmd_found = False
    for keyword in scan_cmds:
        if keyword in cmd:
            cmd_found = True
            break
    is_tool = tool_found or cmd_found

    burst_ports = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3389]
    port_count = sum(1 for p in burst_ports if str(p) in cmd or str(dport) == str(p))
    burst_ports_found = port_count >= 2

    sus_parent = parent.endswith(('cmd.exe', 'powershell.exe', 'winword.exe', 'excel.exe', 'outlook.exe', 'wscript.exe', 'cscript.exe'))

    if is_tool and (burst_ports_found or sus_parent):
        stats.count('service_discovery')
        c = stats.getcount('service_discovery')
        if c >= 2:
            return 1.0
        elif c == 1:
            return 0.75
    return 0.0

def context(event):
    proc = event.get('process_name') or 'Unknown'
    cmd = event.get('command_line') or 'N/A'
    src = event.get('source_ip') or 'Unknown'
    dst = event.get('destination_ip') or 'Unknown'
    dport = event.get('destination_port') or 'N/A'
    par = event.get('parent_process_name') or 'Unknown'

    return (
        "A suspected network service discovery scan (T1046) has been detected involving discovery tactics. "
        "Process '{0}' spawned by '{1}' executed scan command: '{2}'. "
        "Scanning initiated from {3} targeting {4}:{5}. "
        "This activity is categorized under Discovery (TA0007). "
        "Verify if this matches approved scanning schedules or block unsanctioned scans immediately."
    ).format(proc, par, cmd, src, dst, dport)

def criticality():
    c = stats.getcount('service_discovery')
    if c >= 2:
        return 'CRITICAL'
    elif c == 1:
        return 'HIGH'
    return None

def tactic():
    return 'Discovery (TA0007)'

def technique():
    return 'Network Service Discovery (T1046)'

def artifacts():
    return ['host', 'process_name', 'command_line', 'parent_process_name', 'source_ip', 'destination_ip', 'destination_port']

def entity(event):
    return {'derived': False, 'value': event.get('host'), 'type': 'device'}
