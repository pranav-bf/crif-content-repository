"""
Instructions for Workflow Authors:

- Define data extraction logic (e.g., IP, user, artifacts from event)
- Integrate enrichment sources (e.g., threat intelligence APIs)
- Apply evaluation conditions (malicious, suspicious, reputation, tags, categories)
- Add branching logic based on risk signals
- Include session/context analysis for deeper investigation
- Generate a concise summary of findings
- Create incident with conditions met
- Ensure proper handling for clean/no-result scenarios

Upload to MinIO:
  bucket: automation
  key: stream-root-cause-analysis/system_integrity_monitoring/rca.py
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
            "template": (
                "EventSession: retrieved "
                "{{ (output.result|length if output is mapping and output.result is iterable and output.result is not string else (output.rows|length if output is mapping and output.rows is iterable and output.rows is not string else (output|length if output is iterable and output is not string else 'n/a'))) }} "
                "FortiGate system integrity row(s) for RCA "
                "(policy tampering, restarts, FortiAnalyzer, admin lockout, auth alerts)."
            ),
        }, #step 1
        {
            "name": "execute_python_from_s3",
            "parameters": {
                "s3_path": "s3://automation/stream-root-cause-analysis/system_integrity_monitoring/rca.py",
                "function_name": "run_rca",
                "variables": {
                    "sessions": "step.1.output",
                    "event": "event",
                },
            },
            "template": (
                "FortiGate System Integrity RCA completed: "
                "{{ output.verdict if output else 'n/a' }} "
                "(score {{ output.score if output else 'n/a' }}). "
                "Heuristics: allow-all / any-any policy changes, reboots, FortiAnalyzer loss, admin login disable, auth-alert bursts."
            ),
        },#step 2
        {
            "name": "evaluate",
            "parameters": {
                "step": 2,
                "condition": (
                    "output.verdict == 'TRUE_POSITIVE' or output.verdict == 'SUSPICIOUS'"
                ),
                "if_step": 4,
                "else_step": 6,
            },
            "template": "Evaluated the RCA verdict to decide whether to create an incident.",
        },#step 3
        {
            "name": "execute_python",
            "parameters": {
                "code": (
                    "def _row_count(x):\n"
                    "    if isinstance(x, dict):\n"
                    "        r = x.get('result')\n"
                    "        if isinstance(r, list):\n"
                    "            return len(r)\n"
                    "        rows = x.get('rows')\n"
                    "        if isinstance(rows, list):\n"
                    "            return len(rows)\n"
                    "        return 0\n"
                    "    if isinstance(x, list):\n"
                    "        return len(x)\n"
                    "    return 0\n"
                    "\n"
                    "rca_out = rca if isinstance(rca, dict) else {}\n"
                    "arts = rca_out.get('artifacts') if isinstance(rca_out.get('artifacts'), dict) else {}\n"
                    "verdict = rca_out.get('verdict') or 'n/a'\n"
                    "score = rca_out.get('score')\n"
                    "score_text = str(score) if score is not None else 'n/a'\n"
                    "rows = _row_count(sessions)\n"
                    "dev = arts.get('sample_source_device_name') or (arts.get('unique_source_device_names') or [None])[0]\n"
                    "pol = arts.get('sample_policy_id') or (arts.get('unique_policy_ids') or [None])[0]\n"
                    "\n"
                    "title_bits = [f\"FortiGate System Integrity RCA: {verdict} (score {score_text})\"]\n"
                    "if dev:\n"
                    "    title_bits.append(f\"device={dev}\")\n"
                    "if pol:\n"
                    "    title_bits.append(f\"policy={pol}\")\n"
                    "\n"
                    "output = {\n"
                    "  'title': ' | '.join(title_bits),\n"
                    "  'description': (\n"
                    "    f\"Analyzed {rows} FortiGate system/integrity log row(s) for policy tampering (allow-all / any-any), unplanned restarts, \"\n"
                    "    f\"FortiAnalyzer connectivity, administrative login lockout, and high-volume internal auth alert types. \"\n"
                    "    f\"Result: {verdict} with aggregate score {score_text}.\"\n"
                    "  )\n"
                    "}\n"
                ),
                "variables": {
                    "sessions": "step.1.output",
                    "rca": "step.2.output",
                    "event": "event",
                },
            },
            "template": "Incident payload prepared. Title: {{ output.title }}",
        },#step 4
        {
            "name": "action",
            "parameters": {
                "action": "CreateIncident",
                "fields": {
                    "incident": {
                        "step": 4,
                        "path": "output",
                    }
                },
            },
            "template": (
              "{% set inner = output.responses[output.incident_id] "
              "   if output and output.responses and output.incident_id "
              "   and output.incident_id in output.responses "
              "   else (output.responses.values()|list|first "
              "         if output and output.responses else none) %}"
              "{{ inner.result if inner and inner.result is defined else output.incident_id }}"
          ),
        },#step 5
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
        },#step 6
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
        },#step 7
    ]


def template():
    """
    RCA report for the detection UI — System Integrity Monitoring (FortiGate) stream (HTML).

    Report bindings (see ``report_generation.process_message_report``):
      - ``step_0`` … ``step_n`` — outputs from each playbook step (0-based).
      - ``event`` — detection payload from playbook execution document.
    """
    return """<div class="rca-report" style="font-family:system-ui,Segoe UI,sans-serif;line-height:1.45;white-space:normal;">

{%- set s1 = step_0|default({}, true) -%}
{%- set rca = step_1|default({}, true) -%}
{%- set ev = event|default({}, true) -%}
{%- set v = rca.get('verdict') -%}
{%- set score = rca.get('score') -%}
{%- set reason_text = rca.get('reason', '') -%}
{%- set conclusion_text = rca.get('conclusion', '') -%}
{%- set heuristics_html = rca.get('heuristics', '') -%}
{%- set artifacts = rca.get('artifacts') if rca is mapping else none -%}
{%- set rows = (s1.get('result') if s1 is mapping else (s1 if s1 is iterable and s1 is not string else none)) -%}
{%- set _r0 = rows[0] if rows is not none and rows is iterable and rows is not string and rows|length > 0 else none -%}
{%- set dev_hint = (ev.get('source_device_name') or ev.get('hostname') or ev.get('device')) if ev is mapping else none -%}
{%- set dev_hint = dev_hint or ((_r0.get('source_device_name') or _r0.get('hostname')) if _r0 is mapping else none) -%}

{%- set inc_create = step_5|default({}, true) -%}
{%- set incident_dup_id = inc_create.get('incident_id') if inc_create is mapping else none -%}
{%- set resp = inc_create.get('responses') if inc_create is mapping else none -%}
{%- set inner_dup = resp.get(incident_dup_id) if resp is mapping and incident_dup_id else none -%}
{%- set is_incident_dup = (inc_create.get('duplicate') if inc_create is mapping else false) or (inner_dup is mapping and inner_dup.get('data') is mapping and inner_dup.get('data').get('duplicate')) -%}

<div class="rca-body">
  <section class="summary-strip">
    {%- if v == 'TRUE_POSITIVE' -%}
    <strong class="text-danger">High-risk system integrity event</strong>
    <p>The RCA completed and matched strong FortiGate integrity signals (e.g. risky policy change, restarts, logging visibility loss, or admin abuse patterns).</p>
    {%- elif v == 'SUSPICIOUS' -%}
    <strong class="text-warning">Suspicious / elevated signal</strong>
    <p>The RCA completed and found notable signals that warrant validation against change control and device health.</p>
    {%- elif v == 'LOW_RISK' -%}
    <strong>Likely low impact</strong>
    <p>The RCA completed; only weak or single-factor integrity hints were present in the window—confirm context before treatment as a major incident.</p>
    {%- elif v == 'FALSE_POSITIVE' -%}
    <strong>Likely benign / no match</strong>
    <p>The RCA completed, but the monitored FortiGate integrity patterns did not produce a material risk score for this window.</p>
    {%- else -%}
    <strong>RCA pending / unavailable</strong>
    <p>The RCA output is incomplete or pending. Review the session payload and rerun RCA if needed.</p>
    {%- endif -%}
  </section>

  <section class="card rca-block">
    <h2>Session Review</h2>
    <div class="body-copy">
      <p>Loaded FortiGate system/integrity log rows (policy, system, auth) for the detection window.</p>
      <span class="label">Outcome:</span>
      {%- if rows is not none and rows is iterable and rows is not string -%}
      <p>Rows returned: {{ rows|length }} row(s){% if dev_hint %} (sample device <strong>{{ dev_hint }}</strong>){% endif %}.</p>
      {%- elif rows is not none -%}
      <p><strong>Result:</strong> present (non-list shape).</p>
      {%- else -%}
      <p>No session output in this run.</p>
      {%- endif -%}
    </div>
  </section>

  <section class="card rca-block">
    <h2>System integrity findings</h2>
    <div class="body-copy">
      <span class="label">Performed:</span>
      {%- if heuristics_html and heuristics_html|string and heuristics_html.strip() -%}
      <div>{{ heuristics_html }}</div>
      {%- else -%}
      <p>Evaluated FortiGate system integrity heuristics (policy tampering, restart, FortiAnalyzer, admin lockout, internal auth alert volume).</p>
      {%- endif -%}

      <span class="label">Outcome:</span>
      {%- if rca is mapping and rca.get('verdict') -%}
      <p>Verdict: <strong>{{ rca.get('verdict') }}</strong>{% if score is not none %} — aggregate score <strong>{{ score }}</strong>{% endif %}</p>
      {%- else -%}
      <p><em>RCA output not available.</em></p>
      {%- endif -%}

      {%- if reason_text and reason_text.strip() -%}
      <span class="label">Observed signals:</span>
      <p>- {{ reason_text|replace('|', '<br>- ')|safe }}</p>
      {%- endif -%}

      {%- if artifacts is mapping -%}
      <span class="label">Artifacts used:</span>
      <div class="evidence-list">
        {%- if artifacts.get('events_analyzed') is not none -%}
        <div class="evidence-row"><div class="evidence-key">Events</div><div class="evidence-value">{{ artifacts.get('events_analyzed') }} analyzed</div></div>
        {%- endif -%}

        {%- if artifacts.get('unique_source_device_names') is iterable and artifacts.get('unique_source_device_names') is not string and artifacts.get('unique_source_device_names')|length > 0 -%}
        <div class="evidence-row"><div class="evidence-key">Devices</div><div class="evidence-value">{{ artifacts.get('unique_source_device_names')[:3]|join(', ')|e }}{% if artifacts.get('unique_source_device_names')|length > 3 %} <span style="color: rgba(239, 243, 255, 0.56);" title="{{ artifacts.get('unique_source_device_names')|join(', ')|e }}">(+{{ artifacts.get('unique_source_device_names')|length - 3 }} more)</span>{% endif %}</div></div>
        {%- endif -%}

        {%- if artifacts.get('unique_policy_ids') is iterable and artifacts.get('unique_policy_ids') is not string and artifacts.get('unique_policy_ids')|length > 0 -%}
        <div class="evidence-row"><div class="evidence-key">Policy IDs</div><div class="evidence-value">{{ artifacts.get('unique_policy_ids')[:3]|join(', ')|e }}{% if artifacts.get('unique_policy_ids')|length > 3 %} <span style="color: rgba(239, 243, 255, 0.56);" title="{{ artifacts.get('unique_policy_ids')|join(', ')|e }}">(+{{ artifacts.get('unique_policy_ids')|length - 3 }} more)</span>{% endif %}</div></div>
        {%- endif -%}

        {%- if artifacts.get('unique_log_subtypes') is iterable and artifacts.get('unique_log_subtypes') is not string and artifacts.get('unique_log_subtypes')|length > 0 -%}
        <div class="evidence-row"><div class="evidence-key">Log subtypes</div><div class="evidence-value">{{ artifacts.get('unique_log_subtypes')[:3]|join(', ')|e }}{% if artifacts.get('unique_log_subtypes')|length > 3 %} <span style="color: rgba(239, 243, 255, 0.56);" title="{{ artifacts.get('unique_log_subtypes')|join(', ')|e }}">(+{{ artifacts.get('unique_log_subtypes')|length - 3 }} more)</span>{% endif %}</div></div>
        {%- endif -%}

        {%- if artifacts.get('unique_source_ips') is iterable and artifacts.get('unique_source_ips') is not string and artifacts.get('unique_source_ips')|length > 0 -%}
        <div class="evidence-row"><div class="evidence-key">Source IPs</div><div class="evidence-value">{{ artifacts.get('unique_source_ips')[:3]|join(', ')|e }}{% if artifacts.get('unique_source_ips')|length > 3 %} <span style="color: rgba(239, 243, 255, 0.56);" title="{{ artifacts.get('unique_source_ips')|join(', ')|e }}">(+{{ artifacts.get('unique_source_ips')|length - 3 }} more)</span>{% endif %}</div></div>
        {%- endif -%}

        {%- if artifacts.get('unique_destination_ips') is iterable and artifacts.get('unique_destination_ips') is not string and artifacts.get('unique_destination_ips')|length > 0 -%}
        <div class="evidence-row"><div class="evidence-key">Destination IPs</div><div class="evidence-value">{{ artifacts.get('unique_destination_ips')[:3]|join(', ')|e }}{% if artifacts.get('unique_destination_ips')|length > 3 %} <span style="color: rgba(239, 243, 255, 0.56);" title="{{ artifacts.get('unique_destination_ips')|join(', ')|e }}">(+{{ artifacts.get('unique_destination_ips')|length - 3 }} more)</span>{% endif %}</div></div>
        {%- endif -%}

        {%- if artifacts.get('unique_event_alerts') is iterable and artifacts.get('unique_event_alerts') is not string and artifacts.get('unique_event_alerts')|length > 0 -%}
        <div class="evidence-row"><div class="evidence-key">Event alerts</div><div class="evidence-value">{{ artifacts.get('unique_event_alerts')[:3]|join(', ')|e }}{% if artifacts.get('unique_event_alerts')|length > 3 %} <span style="color: rgba(239, 243, 255, 0.56);" title="{{ artifacts.get('unique_event_alerts')|join(', ')|e }}">(+{{ artifacts.get('unique_event_alerts')|length - 3 }} more)</span>{% endif %}</div></div>
        {%- endif -%}

        {%- if artifacts.get('unique_user_names') is iterable and artifacts.get('unique_user_names') is not string and artifacts.get('unique_user_names')|length > 0 -%}
        <div class="evidence-row"><div class="evidence-key">Users</div><div class="evidence-value">{{ artifacts.get('unique_user_names')[:3]|join(', ')|e }}{% if artifacts.get('unique_user_names')|length > 3 %} <span style="color: rgba(239, 243, 255, 0.56);" title="{{ artifacts.get('unique_user_names')|join(', ')|e }}">(+{{ artifacts.get('unique_user_names')|length - 3 }} more)</span>{% endif %}</div></div>
        {%- endif -%}
      </div>
      {%- endif -%}
    </div>
  </section>

  <section class="assessment-panel">
    <h2 class="assessment-title">Final Assessment</h2>
    {%- if is_incident_dup -%}
    <p class="assessment-copy" style="border-left:3px solid #eab308;padding-left:0.75rem;margin-bottom:0.75rem;">
      RCA indicated <strong>{{ v or 'n/a' }}</strong>, but <strong>no new incident</strong> was created — an existing open incident was reused (<strong>{{ incident_dup_id }}</strong>).
      Detection status was set to <strong>FALSE_POSITIVE</strong> for deduplication alignment.
    </p>
    {%- endif -%}
    {%- if v == 'TRUE_POSITIVE' -%}
    <p class="assessment-copy"><strong>Assessment:</strong> FortiGate system integrity patterns indicate <span class="inline-verdict">high impact or high confidence</span> (policy, availability, or admin abuse) — treat as a priority triage item{% if score is not none %}. <strong>Score {{ score }}.</strong>{% endif %}</p>
    {%- elif v == 'SUSPICIOUS' -%}
    <p class="assessment-copy"><strong>Assessment:</strong> <span class="inline-verdict">Suspicious or mixed signals</span> — confirm maintenance windows, recent policy pushes, and FortiAnalyzer health{% if score is not none %}. <strong>Score {{ score }}.</strong>{% endif %}</p>
    {%- elif v == 'LOW_RISK' -%}
    <p class="assessment-copy"><strong>Assessment:</strong> <span class="inline-verdict">Low risk in aggregate</span> for this window — may still be worth a quick operator check for visibility gaps{% if score is not none %}. <strong>Score {{ score }}.</strong>{% endif %}</p>
    {%- elif v == 'FALSE_POSITIVE' -%}
    <p class="assessment-copy"><strong>Assessment:</strong> No material integrity match for the configured rules in this run{% if score is not none %}. <strong>Score {{ score }}.</strong>{% endif %}</p>
    <p class="assessment-copy subtle-line"><strong>Customer / baseline context:</strong> {% if artifacts is mapping and artifacts.get('customer_context') %}{{ artifacts.get('customer_context') }}{% else %}Confirm change approvals, admin roster, and whether broad permit rules or analyzer outages are expected.{% endif %}</p>
    {%- else -%}
    <p class="assessment-copy"><strong>Assessment:</strong> Verdict is <strong>{{ v or 'pending or unavailable' }}</strong>{% if score is not none %}. <strong>Score {{ score }}.</strong>{% endif %}</p>
    {%- endif -%}
  </section>
</div>
<div class="rca-conclusion" data-rca-field="conclusion" style="display:none;">{{ conclusion_text }}</div>
</div>"""
