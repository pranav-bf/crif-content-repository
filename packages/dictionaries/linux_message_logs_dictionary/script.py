import re
from datetime import datetime, timedelta
import calendar



def init(event):
    session.set('dictionary',transform(event))
    return 'initialized'


def criteria(meta):
    return meta.get('provider') == 'Linux' and meta.get('group') == 'OS' \
        and meta.get('type') == 'Security'

def drop(event):
    # message = event.get('msg')
    # message = event.get('msg') or {}
    # return bool(message.get('type') or event.get('source') == 'auditd_log')


    if event.get("source") == "messages_log":
        return False

    return True


def timestamp(event):
    # event=message.get('msg')
    msg = event.get('msg') or {}
    datestring = msg.get("timestamp")
    if not datestring:
        return None

    # Always use UTC clock (machine-independent)
    now_utc = datetime.utcnow()
    current_year = now_utc.year
    current_month = now_utc.month

    # Parse syslog timestamp (no year, IST)
    full_datestring = "%d %s" % (current_year, datestring)
    dt_ist = datetime.strptime(full_datestring, "%Y %b %d %H:%M:%S")

    # Year rollover logic (UTC-safe)
    if dt_ist.month > current_month:
        dt_ist = dt_ist.replace(year=current_year - 1)

    # IST → UTC
    dt_utc = dt_ist - timedelta(hours=5, minutes=30)

    # UTC → epoch milliseconds
    return calendar.timegm(dt_utc.timetuple()) * 1000


def message(event):
    msg = event.get('msg')
    return msg.get('message')

def dictionary(event):
    return session.get('dictionary')



def transform(message):
    # event = message.get('msg')
    event = message.get('msg') or {}
    data = {}
    source_machine_host = message.get('hostname')
    data['source_device_name'] = source_machine_host
    data['host'] = event.get('host')
    data['process_id'] = event.get('pid')
    data['process_name'] = event.get('program')
    data["event_details"] = event.get('message')

    return data