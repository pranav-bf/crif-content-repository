"""
Instructions for Workflow Authors:

- Define data extraction logic (e.g., IP, user, artifacts from event)
- Integrate enrichment sources (e.g., threat intelligence APIs)
- Apply evaluation conditions (malicious, suspicious, reputation, tags, categories)
- Add branching logic based on risk signals
- Include session/context analysis for deeper investigation
- Generate a concise summary of findings
- Create incident with title and description if conditions are met
- Ensure proper handling for clean/no-result scenarios
"""


def steps():
    return [
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
                "Windows Kerberos/ticket session row(s) for RCA. "
                "Gathered evidence for abnormal ticket requests, ticket replay/misuse, and authentication anomalies."
        },# step 1
        {
            "name": "execute_python_from_s3",
            "parameters": {
                "s3_path": "s3://automation/stream-root-cause-analysis/windows_kerberos_and_ticket_activity_monitoring/rca.py",
                "function_name": "run_rca",
                "variables": {
 
                     "sessions": "step.1.output",
                },
            },
            "template": (
                "Windows Kerberos/Ticket RCA completed: "
                "{{ output.verdict if output else 'n/a' }} "
                "(score {{ output.score if output else 'n/a' }}). "
                "Heuristics executed: Kerberos ticket and authentication anomaly checks across sampled sessions."
            ),
        },# step 2
        {
            "name": "evaluate",
            "parameters": {
                "step": 2,
                "condition": "output.verdict == 'TRUE_POSITIVE'",
                "if_step": 4,
                "else_step": 6,
            },
            "template": "Evaluated the RCA verdict to decide whether to create an incident.",
        },# step 3
        {
            "name": "execute_python",
            "parameters": {
                "code": "def _row_count(x):\n    if isinstance(x, dict):\n        r = x.get('result')\n        if isinstance(r, list):\n            return len(r)\n        rows = x.get('rows')\n        if isinstance(rows, list):\n            return len(rows)\n        return 0\n    if isinstance(x, list):\n        return len(x)\n    return 0\n\nrca_out = rca if isinstance(rca, dict) else {}\nverdict = rca_out.get('verdict') or 'n/a'\nscore = rca_out.get('score')\nscore_text = str(score) if score is not None else 'n/a'\nrows = _row_count(sessions)\n\noutput = {\n  'title': f\"Windows Kerberos/Ticket RCA: {verdict} (score {score_text})\",\n  'description': (\n    f\"Analyzed {rows} Windows session row(s) for Kerberos ticket anomalies and suspicious authentication behavior. \"\n    f\"Result: {verdict} with aggregate score {score_text}.\"\n  )\n}\n",
                "variables": {
                    "sessions": "step.1.output",
                    "rca": "step.2.output",
                    "event": "event",
                },
            },
            "template": "Incident payload prepared. Title: {{ output.title }}",
        },# step 4
        {
            "name": "action",
            "parameters": {
                "action": "CreateIncident",
                "fields": {"incident": {"step": 4, "path": "output"}},
            },
            "template": (
              "{% set inner = output.responses[output.incident_id] "
              "   if output and output.responses and output.incident_id "
              "   and output.incident_id in output.responses "
              "   else (output.responses.values()|list|first "
              "         if output and output.responses else none) %}"
              "{{ inner.result if inner and inner.result is defined else output.incident_id }}"
          ),
        },# step 5
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
                    "incident_create": "step.5.output",
                    "rca": "step.2.output",
                },
            },
            "template": (
                "Status verdict for UpdateStatus: {{ output.verdict }} "
                "(FALSE_POSITIVE when incident create was a duplicate)."
            ),
        }, #step 6
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
                        "step": 6,
                        "path": "output.verdict",
                    },
                    "detectiontime": {
                        "step": 0,
                        "path": "detectiontime",
                    },
                },
            },
            "template": "The alert status was modified in accordance with the verdict.",
        }# step 7
    ]


# def template():
#     """
#     RCA report for the detection UI — Palo Alto Authentication Monitor stream (HTML).

#     Report bindings:
#       - ``step_0``, ``step_1`` — outputs from each playbook step (0-based in template).
#       - ``event`` — detection payload from playbook execution document.

#     Variables mirror other Palo Alto RCAs: ``sessions`` from EventSession, ``event`` as fallback.
#     """
#     return """<div class="rca-report" style="font-family:system-ui,Segoe UI,sans-serif;line-height:1.45;white-space:normal;">

# {%- set s1 = step_0|default({}, true) -%}
# {%- set rca = step_1|default({}, true) -%}
# {%- set ev = event|default({}, true) -%}
# {%- set v = rca.get('verdict') -%}
# {%- set score = rca.get('score') -%}
# {%- set reason_text = rca.get('reason', '') -%}
# {%- set conclusion_text = rca.get('conclusion', '') -%}
# {%- set rows = (s1.get('result') if s1 is mapping else (s1 if s1 is iterable and s1 is not string else none)) -%}
# {%- set _r0 = rows[0] if rows is not none and rows is iterable and rows is not string and rows|length > 0 else none -%}
# {%- set user_hint = (ev.get('user_name') or ev.get('user') or ev.get('username')) if ev is mapping else none -%}
# {%- set user_hint = user_hint or ((_r0.get('user_name') or _r0.get('user') or _r0.get('username')) if _r0 is mapping else none) -%}
# {%- set src_ip = (ev.get('source_ip') or ev.get('sourceip') or ev.get('src_ip') or ev.get('src')) if ev is mapping else none -%}
# {%- set src_ip = src_ip or ((_r0.get('source_ip') or _r0.get('src_ip') or _r0.get('src') or _r0.get('sourceip')) if _r0 is mapping else none) -%}

# {%- set inc_create = step_4|default({}, true) -%}
# {%- set incident_dup_id = inc_create.get('incident_id') if inc_create is mapping else none -%}
# {%- set resp = inc_create.get('responses') if inc_create is mapping else none -%}
# {%- set inner_dup = resp.get(incident_dup_id) if resp is mapping and incident_dup_id else none -%}
# {%- set is_incident_dup = (inc_create.get('duplicate') if inc_create is mapping else false) or (inner_dup is mapping and inner_dup.get('data') is mapping and inner_dup.get('data').get('duplicate')) -%}

# <section style="margin:0 0 .85rem 0;">
# <h3 style="font-size:.92rem;margin:.5rem 0 .25rem 0;">Step 1 - Session data</h3>
# <p style="margin:0 0 .25rem 0;">Performed query to retrieve authentication-related session rows for brute-force analysis.</p>
# <p style="margin:0 0 .15rem 0;"><strong>Outcome:</strong></p>
# <ul style="margin:0 0 0 1rem;padding:0;">
# {%- if rows is not none and rows is iterable and rows is not string -%}
# <li><strong>Rows returned:</strong> {{ rows|length }} flow row(s){% if src_ip %} (sample source <strong>{{ src_ip }}</strong>){% endif %}.</li>
# {%- elif rows is not none -%}
# <li><strong>Result:</strong> present (non-list shape).</li>
# {%- else -%}
# <li>No session output in this run.</li>
# {%- endif -%}
# </ul>
# <h3 style="font-size:.92rem;margin:.5rem 0 .25rem 0;">Step 2 - Authentication RCA</h3>
# <p style="margin:0 0 .25rem 0;"><strong>Performed:</strong> Failed login aggregation per source IP and user (brute-force threshold).</p>
# <p style="margin:0 0 .15rem 0;"><strong>Outcome:</strong></p>
# <ul style="margin:0 0 0 1rem;padding:0;">
# {%- if rca is mapping and rca.get('verdict') -%}
# <li><strong>Verdict:</strong> {{ rca.get('verdict') }}{% if score is not none %} - aggregate score <strong>{{ score }}</strong>{% endif %}</li>
# {%- else -%}
# <li><em>RCA output not available.</em></li>
# {%- endif -%}
# </ul>
# </section>
# <hr style="border:0;border-top:1px solid #e0e0e0;margin:.65rem 0;" />
# <section style="margin:0 0 .85rem 0;">
# <h2 style="font-size:1.02rem;margin:0 0 .35rem 0;border-bottom:1px solid #ddd;padding-bottom:.2rem;">Verdict &amp; Risk assessment</h2>
# {%- if is_incident_dup -%}
#     <p class="assessment-copy" style="border-left:3px solid #eab308;padding-left:0.75rem;margin-bottom:0.75rem;">
#       RCA indicated <strong>{{ v or 'n/a' }}</strong>, but <strong>no new incident</strong> was created — an existing open incident was reused (<strong>{{ incident_dup_id }}</strong>).
#       Detection status was set to <strong>FALSE_POSITIVE</strong> for deduplication alignment.
#     </p>
#     {%- endif -%}
# {%- if v == 'TRUE_POSITIVE' -%}
# <p style="margin:0;"><strong>Assessment:</strong> Failed authentication volume supports <strong>likely brute-force activity</strong> for this rule set (many failures from the same source toward the same user){% if score is not none %}. Aggregated risk score is <strong>{{ score }}</strong>{% else %}; no aggregate score recorded{% endif %}.</p>
# {%- elif v == 'SUSPICIOUS' -%}
# <p style="margin:0;"><strong>Assessment:</strong> Findings are <strong>suspicious</strong> — validate password policy, MFA, lockout, and correlated alerts before closing{% if score is not none %}. Score <strong>{{ score }}</strong>{% else %}; no aggregate score recorded{% endif %}.</p>
# {%- elif v == 'FALSE_POSITIVE' -%}
# <p style="margin:0;"><strong>Assessment:</strong> Treated as <strong>false positive / low signal</strong> for brute-force heuristics - failure counts did not exceed the configured threshold{% if score is not none %}. Score <strong>{{ score }}</strong>{% else %}; no aggregate score recorded{% endif %}.</p>
# {%- else -%}
# <p style="margin:0;"><strong>Assessment:</strong> Verdict is <strong>{{ v or 'pending or unavailable' }}</strong>{% if score is not none %} with score <strong>{{ score }}</strong>{% else %}; score not computed{% endif %}.</p>
# {%- endif -%}
# </section>
# {%- if reason_text and reason_text.strip() -%}
# <hr style="border:0;border-top:1px solid #e0e0e0;margin:.65rem 0;" />
# <section style="margin:0;">
# <h2 style="font-size:1.02rem;margin:0 0 .35rem 0;border-bottom:1px solid #ddd;padding-bottom:.2rem;">Findings</h2>
# <ul style="margin:0 0 0 1rem;padding:0;">
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


def template():
    """
    RCA report for the detection UI - Windows Kerberos and ticket activity monitoring stream (HTML).

    Report bindings:
      - ``step_0`` - Windows Kerberos/ticket session telemetry.
      - ``step_1`` - RCA verdict output.
      - ``event`` - detection payload from playbook execution document.
    """
    return """<div class="rca-report" style="font-family:system-ui,Segoe UI,sans-serif;line-height:1.45;white-space:normal;">

{%- set s1 = step_0|default({}, true) -%}
{%- set rca = step_1|default({}, true) -%}
{%- set ev = event|default({}, true) -%}

{%- set v = rca.get('verdict') -%}
{%- set score = rca.get('score') -%}
{%- set reason_text = rca.get('reason', '') -%}
{%- set conclusion_text = rca.get('conclusion', '') -%}
{%- set signals = reason_text.split(' | ') if reason_text and reason_text.strip() else [] -%}

{%- set rows = (s1.get('result') if s1 is mapping and s1.get('result') is not none else (s1.get('rows') if s1 is mapping and s1.get('rows') is not none else (s1 if s1 is iterable and s1 is not string and s1 is not mapping else none))) -%}
{%- set _r0 = rows[0] if rows is not none and rows is iterable and rows is not string and rows|length > 0 else {} -%}

{%- set user_hint = (ev.get('user_name') or ev.get('user') or ev.get('username') or ev.get('target_user_name')) if ev is mapping else none -%}
{%- set user_hint = user_hint or ((_r0.get('user_name') or _r0.get('user') or _r0.get('username') or _r0.get('target_user_name')) if _r0 is mapping else none) -%}
{%- set src_ip = (ev.get('source_ip') or ev.get('sourceip') or ev.get('src_ip') or ev.get('src')) if ev is mapping else none -%}
{%- set src_ip = src_ip or ((_r0.get('source_ip') or _r0.get('sourceip') or _r0.get('src_ip') or _r0.get('src')) if _r0 is mapping else none) -%}
{%- set host = (ev.get('host_name') or ev.get('hostname') or ev.get('computer_name') or ev.get('computer')) if ev is mapping else none -%}
{%- set host = host or ((_r0.get('host_name') or _r0.get('hostname') or _r0.get('computer_name') or _r0.get('computer')) if _r0 is mapping else none) -%}
{%- set service = (ev.get('service_name') or ev.get('target_service_name') or ev.get('service')) if ev is mapping else none -%}
{%- set service = service or ((_r0.get('service_name') or _r0.get('target_service_name') or _r0.get('service')) if _r0 is mapping else none) -%}
{%- set ticket_type = (ev.get('ticket_type') or ev.get('ticket_encryption_type')) if ev is mapping else none -%}
{%- set ticket_type = ticket_type or ((_r0.get('ticket_type') or _r0.get('ticket_encryption_type')) if _r0 is mapping else none) -%}

{%- set inc_create = step_4|default({}, true) -%}
{%- set incident_dup_id = inc_create.get('incident_id') if inc_create is mapping else none -%}
{%- set resp = inc_create.get('responses') if inc_create is mapping else none -%}
{%- set inner_dup = resp.get(incident_dup_id) if resp is mapping and incident_dup_id else none -%}
{%- set is_incident_dup = (inc_create.get('duplicate') if inc_create is mapping else false) or (inner_dup is mapping and inner_dup.get('data') is mapping and inner_dup.get('data').get('duplicate')) -%}

<div class="rca-body">
  <section class="summary-strip">
    {%- if v == 'TRUE_POSITIVE' -%}
    <strong class="text-danger">High-risk Kerberos ticket activity</strong>
    <p>Strong authentication or ticket-abuse evidence matched the configured RCA rules. Review the affected identity, source, and ticket context.</p>
    {%- elif v == 'SUSPICIOUS' -%}
    <strong class="text-warning">Suspicious Kerberos ticket activity</strong>
    <p>Some authentication risk evidence was found, but it did not meet the high-risk threshold.</p>
    {%- elif v == 'FALSE_POSITIVE' -%}
    <strong>False positive</strong>
    <p>The reviewed Kerberos telemetry did not meet the configured risk threshold.</p>
    {%- else -%}
    <strong>RCA pending / unavailable</strong>
    <p>The RCA output is incomplete or unavailable. Review the telemetry and rerun RCA if needed.</p>
    {%- endif -%}
  </section>

  <section class="card rca-block">
    <h2>Session Review</h2>
    <div class="body-copy">
      <p>Retrieved Windows authentication telemetry for the alert window.</p>

      <span class="label">Outcome:</span>
      {%- if rows is not none and rows is iterable and rows is not string -%}
      <p>{{ rows|length }} session row(s) were reviewed for abnormal ticket requests, ticket replay or misuse, and authentication anomalies.</p>
      {%- elif rows is not none -%}
      <p>Session output was present, but returned in a non-list shape.</p>
      {%- else -%}
      <p>No session output was available for this run.</p>
      {%- endif -%}
    </div>
  </section>

  <section class="card rca-block">
    <h2>Kerberos Findings</h2>
    <div class="body-copy">
      <span class="label">Performed:</span>
      <p>Checked ticket-request patterns, replay or misuse indicators, authentication anomalies, and related Windows session context.</p>

      <span class="label">Outcome:</span>
      {%- if rca is mapping and rca.get('verdict') -%}
      <p>Verdict: <strong>{{ v }}</strong>{% if score is not none %} with aggregate score <strong>{{ score }}</strong>{% endif %}.</p>
      {%- else -%}
      <p><em>RCA output was not available.</em></p>
      {%- endif -%}

      {%- if signals -%}
      <span class="label">Signals:</span>
      <div class="evidence-list">
        {%- for signal in signals[:5] -%}
        {%- if signal.strip() -%}
        <div class="evidence-row">
          <div class="evidence-key">Finding</div>
          <div class="evidence-value">{{ signal.strip() }}</div>
        </div>
        {%- endif -%}
        {%- endfor -%}
        {%- if signals|length > 5 -%}
        <div class="evidence-row">
          <div class="evidence-key">More</div>
          <div class="evidence-value">{{ signals|length - 5 }} additional finding(s) were recorded.</div>
        </div>
        {%- endif -%}
      </div>
      {%- else -%}
      <p>No detailed RCA signals were returned.</p>
      {%- endif -%}
    </div>
  </section>

  <section class="card rca-block">
    <h2>Artifacts Used</h2>
    <div class="body-copy">
      <div class="evidence-list">
        <div class="evidence-row"><div class="evidence-key">Session rows</div><div class="evidence-value">{{ rows|length if rows is not none and rows is iterable and rows is not string else 0 }} row(s) analysed</div></div>

        {%- if user_hint -%}
        <div class="evidence-row"><div class="evidence-key">User</div><div class="evidence-value">{{ user_hint|e }}</div></div>
        {%- endif -%}

        {%- if src_ip -%}
        <div class="evidence-row"><div class="evidence-key">Source IP</div><div class="evidence-value">{{ src_ip|e }}</div></div>
        {%- endif -%}

        {%- if host -%}
        <div class="evidence-row"><div class="evidence-key">Host</div><div class="evidence-value">{{ host|e }}</div></div>
        {%- endif -%}

        {%- if service -%}
        <div class="evidence-row"><div class="evidence-key">Service</div><div class="evidence-value">{{ service|e }}</div></div>
        {%- endif -%}

        {%- if ticket_type -%}
        <div class="evidence-row"><div class="evidence-key">Ticket type</div><div class="evidence-value">{{ ticket_type|e }}</div></div>
        {%- endif -%}
      </div>
    </div>
  </section>

  <section class="assessment-panel">
    <h2 class="assessment-title">Final Assessment</h2>
    {%- if is_incident_dup -%}
    <p class="assessment-copy" style="border-left:3px solid #eab308;padding-left:0.75rem;margin-bottom:0.75rem;">
      RCA indicated <strong>{{ v or 'n/a' }}</strong>, but <strong>no new incident</strong> was created - an existing open incident was reused (<strong>{{ incident_dup_id }}</strong>).
      Detection status was set to <strong>FALSE_POSITIVE</strong> for deduplication alignment.
    </p>
    {%- endif -%}
    {%- if v == 'TRUE_POSITIVE' -%}
    <p class="assessment-copy"><strong>Assessment:</strong> The RCA identified <span class="text-danger">high-risk Kerberos ticket activity or suspicious authentication behavior</span>. Investigate the affected identity, source, host, requested service, and correlated Windows security events{% if score is not none %}. <strong>Score {{ score }}.</strong>{% endif %}</p>
    {%- elif v == 'SUSPICIOUS' -%}
    <p class="assessment-copy"><strong>Assessment:</strong> <span class="text-warning">Suspicious Kerberos activity</span> was observed. Validate the ticket requests, account behavior, host context, and related alerts before closing{% if score is not none %}. <strong>Score {{ score }}.</strong>{% endif %}</p>
    {%- elif v == 'FALSE_POSITIVE' -%}
    <p class="assessment-copy"><strong>Assessment:</strong> No meaningful Kerberos abuse evidence met the configured RCA threshold. Treat this as a false positive unless customer context indicates otherwise{% if score is not none %}. <strong>Score {{ score }}.</strong>{% endif %}</p>
    <p class="assessment-copy"><strong>Assessment:</strong> Verdict is <strong>{{ v or 'pending or unavailable' }}</strong>{% if score is not none %}. <strong>Score {{ score }}.</strong>{% endif %}</p>
    {%- endif -%}
  </section>
</div>

<div class="rca-conclusion" data-rca-field="conclusion" style="display:none;">{{ conclusion_text }}</div>
</div>"""