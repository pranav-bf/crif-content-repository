import re
import json
from datetime import datetime, timedelta
import calendar



def init(event):
    session.set('dictionary',transform(event))
    return 'initialized'


def criteria(meta):
    return meta.get('provider') == 'Linux' and meta.get('group') == 'OS' \
        and meta.get('type') == 'Security'

def drop(event):
    msg = event.get('msg', {})
    message_data = msg.get('msg_data', {})
    syscall = (
        clean(message_data.get('SYSCALL'))
        or clean(event.get('SYSCALL'))
        or clean(message_data.get('syscall'))
        or clean(event.get('syscall'))
        or clean(msg.get('SYSCALL'))
          or clean(msg.get('syscall'))
    )
    if event.get("source") == "auditd_log" and str(syscall).lower() not in ['execve', '59'] :
        return False

    return True


def timestamp(event):
    msg = event.get('msg', {})
    ts = msg.get('timestamp')

    if ts is None:
        return None

    return int(float(ts) * 1000)


def message(event):

    d = session.get('dictionary')

    if not d:
        return "An event occurred."

    args = d.get("command_arguments")

    event_type = d.get("event_type") or "event"
    action = d.get("event_action")
    details = d.get("event_details")
    process = d.get("process_name")
    pid = d.get("process_id")
    user = d.get("user_name") or d.get("user_id")
    ip = d.get("source_ip")
    host = d.get("host")

    if event_type == "EXECVE" and args:
        return "Process executed: %s" % " ".join(args)

    parts = []

    parts.append("Event '%s'" % event_type)

    if action:
        parts.append("action '%s'" % action)

    if details:
        parts.append("result '%s'" % details)

    if process:
        if pid:
            parts.append("by process '%s' (PID %s)" % (process, pid))
        else:
            parts.append("by process '%s'" % process)

    if user and user != "(unknown)":
        parts.append("for user '%s'" % user)

    if ip:
        parts.append("from IP %s" % ip)
    elif host:
        parts.append("on host %s" % host)

    return " ".join(parts) + "."

def dictionary(event):
    return session.get('dictionary')



def transform(message):
    data = {}

    source_machine_host = message.get('hostname')
    jumpserver = message.get('jumpserver')

    msg = message.get("msg", {})

    event = msg
    message_data = msg.get("msg_data", {})

    raw_message = message.get("message")

    if raw_message:
        try:
            parsed = json.loads(raw_message)

            source_machine_host = (
                parsed.get("hostname")
                or source_machine_host
            )

            jumpserver = (
                parsed.get("jumpserver")
                or jumpserver
            )

            log_data = parsed.get("log", "")

            hostname_match = re.search(
                r'"hostname":"([^"]+)"',
                log_data
            )

            if hostname_match:
                source_machine_host = hostname_match.group(1)

            type_match = re.search(
                r'type=([A-Z_]+)',
                log_data
            )

            if type_match:
                event["type"] = type_match.group(1)

            argc_match = re.search(
                r'argc=(\d+)',
                log_data
            )

            if argc_match:
                event["argc"] = argc_match.group(1)

            for i in range(50):
                arg_match = re.search(
                    r'a%s=\\?"([^"]*)\\?"' % i,
                    log_data
                )

                if arg_match:
                    event["a%s" % i] = arg_match.group(1)

            audit_match = re.search(
                r'audit\(([\d\.]+):(\d+)\)',
                log_data
            )

            if audit_match:
                event["timestamp"] = audit_match.group(1)
                event["seq"] = audit_match.group(2)

        except Exception:
            pass

    data['source_device_name'] = clean(source_machine_host)
    data['jumpserver'] = clean(jumpserver)

    data['event_type'] = clean(event.get('type'))

    data['process_id'] = clean(event.get('pid'))

    data['user_id'] = clean(
        event.get('UID')
        or event.get('uid')
        or event.get('AUID')
        or event.get('auid')
    )

    data['process_path'] = clean(
        message_data.get('exe')
    ) or clean(
        event.get('exe')
    )

    data['user_name'] = clean(
        message_data.get('acct')
    ) or clean(
        event.get('acct')
    )

    data['event_action'] = clean(
        message_data.get('op')
    ) or clean(
        event.get('op')
    )

    data['event_details'] = clean(
        message_data.get('res')
    ) or clean(
        event.get('res')
    )

    data['source_ip'] = clean(
        message_data.get('addr')
    ) or clean(
        event.get('addr')
    )

    data['host'] = clean(
        message_data.get('hostname')
    ) or clean(
        event.get('hostname')
    )

    data['process_command'] = clean(
        message_data.get('cmd')
        or message_data.get('comm')
    ) or clean(
        event.get('cmd')
        or event.get('comm')
    )

    data['terminal'] = clean(
        message_data.get('terminal')
    ) or clean(
        event.get('terminal')
    )

    data['file_path'] = clean(
        message_data.get('cwd')
    ) or clean(
        event.get('cwd')
    )

    data['proctitle'] = clean(
        message_data.get('proctitle')
    ) or clean(
        event.get('proctitle')
    )

    if data.get('process_command'):
        data['process_name'] = data['process_command']

    elif data.get('process_path'):
        data['process_name'] = (
            data['process_path'].rsplit("/", 1)[-1]
        )

    event_type = str(
        data.get('event_type', '')
    ).upper()

    syscall = (
        clean(message_data.get('SYSCALL'))
        or clean(event.get('SYSCALL'))
        or clean(message_data.get('syscall'))
        or clean(event.get('syscall'))
    )

    is_execve_event = (
        event_type == 'EXECVE'
        or str(syscall).lower() in ['execve', '59']
    )

    if is_execve_event:

        args = []

        try:
            argument_count = int(
                event.get("argc")
                or 0
            )

        except (ValueError, TypeError):
            argument_count = 0

        for i in range(argument_count):

            value = event.get(
                'a%s' % i
            )

            if value is not None:
                args.append(value)

        if args:
            data['command_arguments'] = args

    ts = clean(event.get('timestamp'))
    seq = clean(event.get('seq'))

    if ts is not None and seq is not None:
        data['audit_id'] = "%s:%s" % (
            ts,
            seq
        )

    return data
def clean(value):
    return None if value in (None, "?", "") else value