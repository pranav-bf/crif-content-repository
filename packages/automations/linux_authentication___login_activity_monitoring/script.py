"""
Root Cause Analysis for SIEM Stream: Linux Authentication & Login Activity Monitoring

Detections covered:
- Multiple Failed Login Attempts For Linux
- FTP Authentication Failure
- Multiple Password Check Failed For User
- SSH Login During Off-Hours
- Successful Root Login via SSH
- Abnormal Sudo Usage
- Sudo Command from Root Directory
"""

def steps():
    return [
        # step 1
        {
            "name": "action",
            "parameters": {
                "action": "DictionaryEventSession",
                "fields": {
                    "event": {
                        "step": 0,
                        "path": "event",
                    }
                },
            },
            "template": "EventSession: retrieved "
                "{{ (output.result|length if output is mapping and output.result is iterable and output.result is not string else (output.rows|length if output is mapping and output.rows is iterable and output.rows is not string else (output|length if output is iterable and output is not string else 'n/a'))) }} "
                "Linux authentication session row(s) for RCA. "
                "Gathered login failures, SSH anomalies, and sudo usage evidence across sampled sessions."
        },
        # step 2
        {
            "name": "execute_python_from_s3",
            "parameters": {
                "s3_path": "s3://automation/stream-root-cause-analysis/linux_authentication_login_activity_monitoring/rca.py",
                "function_name": "extract_artifacts",
                "variables": {"sessions": "step.1.output"},
            },
            "template": "Extracted distinct source IPs from Linux authentication events for enrichment.",
        },
        # step 3
        {
            "name": "threatlab",
            "parameters": {
                "threat_intel_id": "threatintel.abuseipdb.lookup_ip",
                "input": {
                    "ip": "step.2.output.source_ips",
                    "days": 90,
                    "verbose": "yes"
                }
            },
            "template": (
                "AbuseIPDB enrichment executed for extracted source IPs."
            )
        },
        # step 4
        {
            "name": "execute_python_from_s3",
            "parameters": {
                "s3_path": "s3://automation/stream-root-cause-analysis/linux_authentication_login_activity_monitoring/rca.py",
                "function_name": "run_rca",
                "variables": {
                    "sessions": "step.1.output",
                    "event": "event",
                    "abuseipdb": "step.3.output",
                },
            },
            "template": (
                "Linux Authentication RCA completed: "
                "{{ output.verdict if output else 'n/a' }} "
                "(score {{ output.score if output else 'n/a' }}). "
                "Heuristics executed: authentication failure analysis, root SSH validation, privilege escalation analysis, and sudo activity evaluation."
            ),
        },
        # step 5
        {
            "name": "evaluate",
            "parameters": {
                "step": 4,
                "condition": "output.verdict == 'TRUE_POSITIVE'",
                "if_step": 6,
                "else_step": 8
            },
            "template": "Evaluated the RCA verdict to decide whether to create an incident."
        },
        # step 6
        {
            "name": "execute_python",
            "parameters": {
                "code": "def _row_count(x):\n    if isinstance(x, dict):\n        r = x.get('result')\n        if isinstance(r, list):\n            return len(r)\n        rows = x.get('rows')\n        if isinstance(rows, list):\n            return len(rows)\n        return 0\n    if isinstance(x, list):\n        return len(x)\n    return 0\n\nrca_out = rca if isinstance(rca, dict) else {}\nverdict = rca_out.get('verdict') or 'n/a'\nscore = rca_out.get('score')\nscore_text = str(score) if score is not None else 'n/a'\nrows = _row_count(sessions)\n\noutput = {\n  'title': f\"Linux Authentication/Login RCA: {verdict} (score {score_text})\",\n  'description': (\n    f\"Analyzed {rows} Linux authentication session row(s) for login failures, SSH anomalies, and sudo usage patterns. \"\n    f\"Result: {verdict} with aggregate score {score_text}.\"\n  )\n}",
                "variables": {
                    "sessions": "step.1.output",
                    "rca": "step.4.output",
                    "event": "event"
                }
            },
            "template": "Incident payload prepared. Title: {{ output.title }}"
        },
        # step 7
        {
            "name": "action",
            "parameters": {
                "action": "CreateIncident",
                "fields": {
                    "incident": {
                        "step": 6,
                        "path": "output"
                    }
                }
            },
            "template": (
              "{% set inner = output.responses[output.incident_id] "
              "   if output and output.responses and output.incident_id "
              "   and output.incident_id in output.responses "
              "   else (output.responses.values()|list|first "
              "         if output and output.responses else none) %}"
              "{{ inner.result if inner and inner.result is defined else output.incident_id }}"),
        },
        # step 8
        {
            "name": "execute_python",
            "parameters": {
                "code": (
                    "def _rca_verdict(rca):\n"
                    "    if not isinstance(rca, dict):\n"
                    "        return 'n/a'\n"
                    "    out = rca.get('output')\n"
                    "    if isinstance(out, dict) and out.get('verdict'):\n"
                    "        return out.get('verdict')\n"
                    "    return rca.get('verdict') or 'n/a'\n"
                    "\n"
                    "def _incident_duplicate(inc):\n"
                    "    if not isinstance(inc, dict):\n"
                    "        return False\n"
                    "    if inc.get('duplicate') is True:\n"
                    "        return True\n"
                    "    resp = inc.get('responses') or {}\n"
                    "    if not isinstance(resp, dict):\n"
                    "        return False\n"
                    "    for inner in resp.values():\n"
                    "        if not isinstance(inner, dict):\n"
                    "            continue\n"
                    "        data = inner.get('data') or {}\n"
                    "        if isinstance(data, dict) and data.get('duplicate') is True:\n"
                    "            return True\n"
                    "    return False\n"
                    "\n"
                    "if _incident_duplicate(incident_create):\n"
                    "    verdict = 'FALSE_POSITIVE'\n"
                    "else:\n"
                    "    verdict = _rca_verdict(rca)\n"
                    "\n"
                    "output = {'verdict': verdict}\n"
                ),
                "variables": {
                    "incident_create": "step.7.output",
                    "rca": "step.4.output"
                },
            },
            "template": (
                "Status verdict for UpdateStatus: {{ output.verdict }} "
                "(FALSE_POSITIVE when incident create was a duplicate)."
            ),
        },
        # STEP 9
        {
            "name": "action",
            "parameters": {
                "action": "UpdateStatus",
                "fields": {
                    "id": {
                        "step": 0,
                        "path": "id",
                    },
                    "verdict": {
                        "step": 8,
                        "path": "output.verdict",
                    },
                    "detectiontime": {
                        "step": 0,
                        "path": "detectiontime",
                    },
                },
            },
            "template": "The alert status was modified in accordance with the verdict.",
        }
    ]


def template():
    """
    RCA report for the detection UI — Linux Authentication & Login Activity Monitoring (HTML).

    Report bindings:
      - ``step_0`` — Linux authentication session telemetry.
      - ``step_1`` — extracted artifacts.
      - ``step_2`` — AbuseIPDB enrichment output.
      - ``step_3`` — RCA verdict output.
      - ``event`` — detection payload from playbook execution document.
    """
    return """<div class="rca-report" style="font-family:system-ui,Segoe UI,sans-serif;line-height:1.45;white-space:normal;">

{%- set s1 = step_0|default({}, true) -%}
{%- set artifacts = step_1 if step_1 is defined and step_1 is mapping else {} -%}
{%- set abuseip_data = step_2 if step_2 is defined and step_2 is mapping else {} -%}
{%- set rca = step_3|default({}, true) -%}

{%- set v = rca.get('verdict') if rca is mapping else none -%}
{%- set score = rca.get('score') if rca is mapping else none -%}
{%- set reason_text = rca.get('reason', '') if rca is mapping else '' -%}
{%- set conclusion_text = rca.get('conclusion', '') if rca is mapping else '' -%}

{%- set rows = (s1.get('result') if s1 is mapping else (s1 if s1 is iterable and s1 is not string else none)) -%}
{%- set src_ips = artifacts.get('source_ips') or [] -%}
{%- set hosts = artifacts.get('hosts') or [] -%}
{%- set users = artifacts.get('users') or [] -%}
{%- set processes = artifacts.get('process_names') or [] -%}
{%- set signals = rca.get('observed_signals', []) -%}

{%- set abuseip_hits = [] -%}
{%- set abuseip_responses = abuseip_data.get('responses', {}) if abuseip_data is mapping else {} -%}
{%- if abuseip_responses is mapping -%}
  {%- for ip, result in abuseip_responses.items() -%}
    {%- set response = result.get('response', {}) if result is mapping else {} -%}
    {%- set data = response.get('data', {}) if response is mapping else {} -%}
    {%- set data = data if data else (result.get('data', result) if result is mapping else {}) -%}
    {%- set confidence = data.get('abuseConfidenceScore', 0)|int if data is mapping else 0 -%}
    {%- set reports = data.get('totalReports', 0)|int if data is mapping else 0 -%}
    {%- if confidence > 0 -%}
      {%- set _ = abuseip_hits.append({'ip': ip, 'confidence': confidence, 'reports': reports}) -%}
    {%- endif -%}
  {%- endfor -%}
{%- endif -%}

{%- set inc_create = step_7|default({}, true) -%}
{%- set incident_dup_id = inc_create.get('incident_id') if inc_create is mapping else none -%}
{%- set resp = inc_create.get('responses') if inc_create is mapping else none -%}
{%- set inner_dup = resp.get(incident_dup_id) if resp is mapping and incident_dup_id else none -%}
{%- set is_incident_dup = (inc_create.get('duplicate') if inc_create is mapping else false) or (inner_dup is mapping and inner_dup.get('data') is mapping and inner_dup.get('data').get('duplicate')) -%}

<div class="rca-body">
  <section class="summary-strip">
    {%- if v == 'TRUE_POSITIVE' -%}
    <strong class="text-danger">High-risk Linux authentication activity</strong>
    <p>Authentication telemetry and source IP reputation indicate malicious activity.</p>
    {%- elif v == 'FALSE_POSITIVE' -%}
    <strong>Likely benign / false positive</strong>
    <p>The reviewed telemetry and enrichment did not meet the configured risk threshold.</p>
    {%- else -%}
    <strong>RCA pending / unavailable</strong>
    <p>The RCA output is incomplete or unavailable.</p>
    {%- endif -%}
  </section>

  <section class="card rca-block">
    <h2>Session Review</h2>
    <div class="body-copy">
      <p>Retrieved Linux authentication and login activity telemetry for the alert window.</p>
      <span class="label">Outcome:</span>
      {%- if rows is not none and rows is iterable and rows is not string -%}
      <p>{{ rows|length }} telemetry row(s) were reviewed.</p>
      {%- elif rows is not none -%}
      <p>Session output was present, but returned in a non-list shape.</p>
      {%- else -%}
      <p>No session output was available for this run.</p>
      {%- endif -%}
    </div>
  </section>

  <section class="card rca-block">
    <h2>Authentication Findings</h2>
    <div class="body-copy">
      <span class="label">Performed:</span>
      <p>Checked authentication failures, FTP authentication failures, SSH authentication activity, root account access, privilege escalation activity, sudo execution activity, and source IP reputation.</p>

      <span class="label">Outcome:</span>
      {%- if v -%}
      <p>Verdict: <strong>{{ v }}</strong>{% if score is not none %} - aggregate score <strong>{{ score }}</strong>{% endif %}.</p>
      {%- else -%}
      <p><em>RCA output was not available.</em></p>
      {%- endif -%}

      <span class="label">Observed Signals:</span>
      {%- if signals|length > 0 -%}
      <p>
        {%- for signal in signals -%}
        - {{ signal|e }}{% if not loop.last %}<br>{% endif %}
        {%- endfor -%}
      </p>
      {%- else -%}
      <p>- No strong malicious behaviors were identified from available telemetry.</p>
      {%- endif -%}

      <span class="label">Reputation Summary:</span>
      <div class="evidence-list">
        <div class="evidence-row">
          <div class="evidence-key">Flagged Source IPs</div>
          <div class="evidence-value">{{ abuseip_hits|length }} source IP(s) with reputation concerns</div>
        </div>
      </div>

      {%- if abuseip_hits|length > 0 -%}
      <span class="label">Flagged IP Details:</span>
      <div class="evidence-list">
        {%- for hit in abuseip_hits[:3] -%}
        <div class="evidence-row">
          <div class="evidence-key">AbuseIPDB</div>
          <div class="evidence-value">
            <strong>{{ hit.ip }}</strong><br>
            {% if hit.confidence >= 80 %}malicious{% else %}suspicious{% endif %}
            reputation - confidence {{ hit.confidence }}, {{ hit.reports }} report(s)
          </div>
        </div>
        {%- endfor -%}
      </div>
      {%- endif -%}
    </div>
  </section>

  <section class="card rca-block">
    <h2>Artifacts Used</h2>
    <div class="body-copy">
      <div class="evidence-row"><div class="evidence-key">Observed Signals</div>
  <div class="evidence-value">{% if signals %}{{ signals[:3]|join(', ')|e }}
    {% else %} 0 finding(s)
    {% endif %}
  </div>
</div>

      {%- if src_ips|length > 0 -%}
      <div class="evidence-row"><div class="evidence-key">Source IPs</div><div class="evidence-value">{{ src_ips[:3]|join(', ')|e }}{% if src_ips|length > 3 %} <span title="{{ src_ips|join(', ')|e }}">(+{{ src_ips|length - 3 }} more)</span>{% endif %}</div></div>
      {%- endif -%}

      {%- if hosts|length > 0 -%}
      <div class="evidence-row"><div class="evidence-key">Hosts</div><div class="evidence-value">{{ hosts[:3]|join(', ')|e }}{% if hosts|length > 3 %} <span title="{{ hosts|join(', ')|e }}">(+{{ hosts|length - 3 }} more)</span>{% endif %}</div></div>
      {%- endif -%}

      {%- if processes|length > 0 -%}
      <div class="evidence-row"><div class="evidence-key">Process names</div><div class="evidence-value">{{ processes[:3]|join(', ')|e }}</div></div>
      {%- endif -%}
    </div>
  </section>

  <section class="assessment-panel">
    <h2 class="assessment-title">Final Assessment</h2>
    {%- if is_incident_dup -%}
    <p class="assessment-copy" style="border-left:3px solid #eab308;padding-left:0.75rem;margin-bottom:0.75rem;">
      RCA indicated <strong>{{ v or 'n/a' }}</strong>, but <strong>no new incident</strong> was created - an existing open incident was reused (<strong>{{ incident_dup_id }}</strong>).
      Detection status was set to <strong>FALSE_POSITIVE</strong> for deduplication alignment.
    </p>
    {%- elif v == 'TRUE_POSITIVE' -%}
    <p class="assessment-copy">
    <strong>Assessment:</strong>
    High-risk malicious Linux authentication activity was identified{% if score is not none %}. <strong>Score {{ score }}.</strong>{% endif %}
    </p>
    {%- elif v == 'FALSE_POSITIVE' -%}
    <p class="assessment-copy">
    <strong>Assessment:</strong>
    No meaningful authentication threat evidence met the configured RCA threshold{% if score is not none %}. <strong>Score {{ score }}.</strong>{% endif %}
    </p>
    {%- else -%}
    <p class="assessment-copy">
    <strong>Assessment:</strong>
    Verdict is <strong>{{ v or 'pending or unavailable' }}</strong>.
    </p>
    {%- endif -%}
  </section>
</div>

<div class="rca-conclusion" data-rca-field="conclusion" style="display:none;">{{ conclusion_text }}</div>
</div>"""

# def steps():
#     return [
#         {
#             "name": "action",
#             "parameters": {
#                 "action": "DictionaryEventSession",
#                 "fields": {
#                     "event": {
#                         "step": 0,
#                         "path": "event",
#                     }
#                 },
#             },
#             "template": "EventSession: retrieved "
#                 "{{ (output.result|length if output is mapping and output.result is iterable and output.result is not string else (output.rows|length if output is mapping and output.rows is iterable and output.rows is not string else (output|length if output is iterable and output is not string else 'n/a'))) }} "
#                 "Linux authentication session row(s) for RCA. "
#                 "Gathered login failures, SSH anomalies, and sudo usage evidence across sampled sessions."
#         },
#         {
#             "name": "execute_python_from_s3",
#             "parameters": {
#                 "s3_path": "s3://automation/stream-root-cause-analysis/utils/extract_distinct_ips.py",
#                 "function_name": "extract_distinct_ips",
#                 "variables": {"sessions": "step.1.output"},
#             },
#             "template": "Extracted distinct destination IPs from session rows for enrichment.",
#         },
#         {
#             "name": "threatlab",
#             "parameters": {
#                 "threat_intel_id": "threatintel.virustotalv3.ip_reputation",
#                 "input": {
#                     # List fan-out supported: executor will call VirusTotal once per IP.
#                     "ip": "step.2.output"
#                 },
#             },
#             "template":  "VirusTotal enrichment executed for destination IP(s) "
#                 "(fan-out supported when IP list is provided)."
#         },
#         {
#             "name": "execute_python_from_s3",
#             "parameters": {
#                 "s3_path": "s3://automation/stream-root-cause-analysis/linux_authentication_login_activity_monitoring/rca.py",
#                 "function_name": "run_rca",
#                 "variables": {
#                     "sessions": "step.1.output",
#                     "event": "event",
#                     "threatlab_execute": "step.3.output",
#                 },
#             },
#             "template": (
#                 "Linux Authentication RCA completed: "
#                 "{{ output.verdict if output else 'n/a' }} "
#                 "(score {{ output.score if output else 'n/a' }}). "
#                 "Heuristics executed: login failure analysis, SSH anomaly checks, and sudo usage evaluation "
#             ),
#         },
#         {
#             "name": "evaluate",
#             "parameters": {
#                 "step": 2,
#                 "condition": "output.verdict == 'TRUE_POSITIVE'",
#                 "if_step": 4,
#                 "else_step": 6
#             },
#             "template": "Evaluated the RCA verdict to decide whether to create an incident."
#         },
#         {
#             "name": "execute_python",
#             "parameters": {
#                 "code": "def _row_count(x):\n    if isinstance(x, dict):\n        r = x.get('result')\n        if isinstance(r, list):\n            return len(r)\n        rows = x.get('rows')\n        if isinstance(rows, list):\n            return len(rows)\n        return 0\n    if isinstance(x, list):\n        return len(x)\n    return 0\n\nrca_out = rca if isinstance(rca, dict) else {}\nverdict = rca_out.get('verdict') or 'n/a'\nscore = rca_out.get('score')\nscore_text = str(score) if score is not None else 'n/a'\nrows = _row_count(sessions)\n\noutput = {\n  'title': f\"Linux Authentication/Login RCA: {verdict} (score {score_text})\",\n  'description': (\n    f\"Analyzed {rows} Linux authentication session row(s) for login failures, SSH anomalies, and sudo usage patterns. \"\n    f\"Result: {verdict} with aggregate score {score_text}.\"\n  )\n}",
#                 "variables": {
#                     "sessions": "step.1.output",
#                     "rca": "step.2.output",
#                     "event": "event"
#                 }
#             },
#             "template": "Incident payload prepared. Title: {{ output.title }}"
#         },
#         {
#             "name": "action",
#             "parameters": {
#                 "action": "CreateIncident",
#                 "fields": {
#                     "incident": {
#                         "step": 4,
#                         "path": "output"
#                     }
#                 }
#             },
#             "template": "Incident created successfully. ID: {{ output.incident_id if output else 'Unknown' }}."
#         },
#         {
#             "name": "action",
#             "parameters": {
#                 "action": "UpdateStatus",
#                 "fields": {
#                     "id":{
#                         "step": 0,
#                         "path": "id"
#                     },
#                     "verdict":{
#                         "step": 2,
#                         "path": "output.verdict"
#                     }
#                 }
#             },
#             "template": "The alert status was modified in accordance with the verdict."
#         }
#     ]


# def template():
#     """
#     RCA report for the detection UI — Palo Alto Threat Intelligence stream (HTML).

#     Report bindings (see genai-playbook-executor ``report_generation.process_message_report``):
#       - ``step_1`` … ``step_n`` — outputs from each playbook step.
#       - ``event`` — detection payload from Mongo ``playbook`` execution document
#         (``data_manager.get_execution_event(execution_id)``), same object passed into
#         the run as ``event`` in steps. Use ``event.destination_ip`` if your payload
#         includes it; otherwise the template falls back to session row fields.

#     If ``event`` is empty in the report, confirm the executor build includes the
#     report context merge and that executions store an ``event`` field.
#     """
#     # Jinja emits newlines around {% %} by default — use {%- -%} so the UI does not show huge gaps
#     # (plain LLM text has no Jinja noise). Root sets white-space: normal to override parent pre-wrap.
#     return """<div class="rca-report" style="font-family:system-ui,Segoe UI,sans-serif;line-height:1.45;white-space:normal;">

# {%- set s1 = step_0|default({}, true) -%}
# {%- set extracted_ips = step_1|default([], true) -%}
# {%- set s2 = step_2|default({}, true) -%}
# {%- set rca = step_3|default({}, true) -%}
# {%- set ev = event|default({}, true) -%}
# {%- set v = rca.get('verdict') -%}
# {%- set score = rca.get('score') -%}
# {%- set reason_text = rca.get('reason', '') -%}
# {%- set conclusion_text = rca.get('conclusion', '') -%}
# {%- set rows = (s1.get('result') if s1 is mapping else (s1 if s1 is iterable and s1 is not string else none)) -%}
# {%- set _r0 = rows[0] if rows is not none and rows is iterable and rows is not string and rows|length > 0 else none -%}

# <section style="margin:0 0 .85rem 0;">
# <h3 style="font-size:.92rem;margin:.5rem 0 .25rem 0;">Step 1 - Session data</h3>
# <p style="margin:0 0 .25rem 0;">Performed query to retrieve session data.</p>
# <p style="margin:0 0 .15rem 0;"><strong>Outcome:</strong></p>
# <ul style="margin:0 0 0 1rem;padding:0;">
# {%- if rows is not none and rows is iterable and rows is not string -%}
# <li><strong>Rows returned:</strong> {{ rows|length }} session row(s).</li>
# {%- elif rows is not none -%}
# <li><strong>Result:</strong> present (non-list shape).</li>
# {%- else -%}
# <li>No session output in this run.</li>
# {%- endif -%}
# </ul>
# <h3 style="font-size:.92rem;margin:.5rem 0 .25rem 0;">Step 2 - Distinct destination IPs</h3>
# <p style="margin:0 0 .25rem 0;">Computed distinct destination IPs from session rows for ThreatLab enrichment.</p>
# <p style="margin:0 0 .15rem 0;"><strong>Outcome:</strong></p>
# <ul style="margin:0 0 0 1rem;padding:0;">
# {%- if extracted_ips is iterable and extracted_ips is not string -%}
# <li><strong>Unique destination IPs:</strong> {{ extracted_ips|length }}{% if extracted_ips|length > 0 %} (sample <strong>{{ extracted_ips[0] }}</strong>){% endif %}</li>
# {%- else -%}
# <li>No extracted IPs in this run.</li>
# {%- endif -%}
# </ul>
# <h3 style="font-size:.92rem;margin:.5rem 0 .25rem 0;">Step 3 - Threat intelligence (AbuseIPDB)</h3>
# <p style="margin:0 0 .25rem 0;"><strong>Performed:</strong> Lookup IP reputation for{% if extracted_ips is iterable and extracted_ips is not string and extracted_ips|length > 0 %} <strong>{{ extracted_ips|length }}</strong> destination IP(s): <strong>{{ (extracted_ips[:6])|join(', ') }}</strong>{% if extracted_ips|length > 6 %} <em style="color:#666;">(+{{ extracted_ips|length - 6 }} more)</em>{% endif %}{% else %} <em style="color:#666;">(IP not resolved)</em>{% endif %}.</p>
# <p style="margin:0 0 .15rem 0;"><strong>Outcome:</strong></p>
# <ul style="margin:0 0 0 1rem;padding:0;">
# {%- if s2 is mapping -%}
# {%- set _resp_map = s2.get('responses') if s2.get('responses') is mapping else none -%}
# {%- set _one = (_resp_map.values()|list)[0] if _resp_map is not none and (_resp_map|length) > 0 else s2 -%}
# <li>{% if s2.get('message') %} - {{ s2.get('message') }}{% endif %}{% if _one.get('response') and _one.get('response').get('data') %} with abuse confidence score {{ _one.get('response').get('data').get('abuseConfidenceScore') }} and total reports {{ _one.get('response').get('data').get('totalReports') }}{% endif %}</li>
# {%- else -%}
# <li><em>ThreatLab output not available.</em></li>
# {%- endif -%}
# </ul>
# </section>
# <hr style="border:0;border-top:1px solid #e0e0e0;margin:.65rem 0;" />
# <section style="margin:0 0 .85rem 0;">
# <h2 style="font-size:1.02rem;margin:0 0 .35rem 0;border-bottom:1px solid #ddd;padding-bottom:.2rem;">Verdict &amp; Risk assessment</h2>
# {%- if v == 'TRUE_POSITIVE' -%}
# <p style="margin:0;"><strong>Assessment:</strong> This detection is classified as <strong>confirmed malicious or high-fidelity threat activity</strong> (exploit signatures, C2 indicators, or repeated threat volume support escalation){% if score is not none %}. The aggregated risk score is <strong>{{ score }}</strong>, combining session threat signals with ThreatLab context{% else %}; no aggregate risk score was computed for this run{% endif %}.</p>
# {%- elif v == 'SUSPICIOUS' -%}
# <p style="margin:0;"><strong>Assessment:</strong> Findings are <strong>suspicious</strong> - validate signatures and destinations, correlate with TI, asset ownership, and patch posture before closing{% if score is not none %}. Aggregated risk score <strong>{{ score }}</strong>{% else %}; no aggregate risk score was computed{% endif %}.</p>
# {%- elif v == 'FALSE_POSITIVE' -%}
# <p style="margin:0;"><strong>Assessment:</strong> Treated as <strong>false positive / likely benign</strong> for this rule set - no strong threat signal from the analyzed event and related sessions{% if score is not none %}. Aggregated risk score <strong>{{ score }}</strong>{% else %}; no aggregate risk score was computed{% endif %}.</p>
# {%- else -%}
# <p style="margin:0;"><strong>Assessment:</strong> Verdict is <strong>{{ v or 'pending or unavailable' }}</strong>{% if score is not none %} with aggregate RCA risk score <strong>{{ score }}</strong>{% else %}; risk score was not computed{% endif %}.</p>
# {%- endif -%}
# </section>
# {%- if reason_text and reason_text.strip() -%}
# <hr style="border:0;border-top:1px solid #e0e0e0;margin:.65rem 0;" />
# <section style="margin:0;">
# <h2 style="font-size:1.02rem;margin:0 0 .35rem 0;border-bottom:1px solid #ddd;padding-bottom:.2rem;">Findings</h2>
# <ul style="margin:0;padding:0;">
# {%- for clause in reason_text.split(' | ') -%}
# {%- if clause.strip() -%}
# <li>{{ clause.strip() }}</li>
# {%- endif -%}
# {%- endfor -%}
# </ul>
# </section>
# {%- endif -%}
# <div class="rca-conclusion" data-rca-field="conclusion" style="display:none;">{{ conclusion_text }}</div>
# </div>"""
