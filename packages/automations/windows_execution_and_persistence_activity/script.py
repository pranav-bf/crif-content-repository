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
                "Windows execution/persistence session row(s) for RCA. "
                "Gathered evidence for suspicious process execution and persistence mechanisms."
        },# step 1
        {
            "name": "execute_python_from_s3",
            "parameters": {
                "s3_path": "s3://automation/stream-root-cause-analysis/windows_execution_and_persistence_activity_monitoring/rca.py",
                "function_name": "run_rca",
                "variables": {
 
                    "sessions": "step.1.output",
                },
            },
            "template": (
                "Windows Execution/Persistence RCA completed: "
                "{{ output.verdict if output else 'n/a' }} "
                "(score {{ output.score if output else 'n/a' }}). "
                "Heuristics executed: execution anomaly and persistence indicator checks across sampled sessions."
            ),
        },# step 2
        {
            "name": "evaluate",
            "parameters": {
                "step": 2,
                "condition": "output.verdict == 'TRUE_POSITIVE'",
                "if_step": 4,
                "else_step": 6
            },
            "template": "Evaluated the RCA verdict to decide whether to create an incident."
        },# step 3
        {
            "name": "execute_python",
            "parameters": {
                "code": "def _row_count(x):\n    if isinstance(x, dict):\n        r = x.get('result')\n        if isinstance(r, list):\n            return len(r)\n        rows = x.get('rows')\n        if isinstance(rows, list):\n            return len(rows)\n        return 0\n    if isinstance(x, list):\n        return len(x)\n    return 0\n\nrca_out = rca if isinstance(rca, dict) else {}\nverdict = rca_out.get('verdict') or 'n/a'\nscore = rca_out.get('score')\nscore_text = str(score) if score is not None else 'n/a'\nrows = _row_count(sessions)\n\noutput = {\n  'title': f\"Windows Execution/Persistence RCA: {verdict} (score {score_text})\",\n  'description': (\n    f\"Analyzed {rows} Windows session row(s) for suspicious execution and persistence mechanisms. \"\n    f\"Result: {verdict} with aggregate score {score_text}.\"\n  )\n}",
                "variables": {
                    "sessions": "step.1.output",
                    "rca": "step.2.output",
                    "event": "event"
                }
            },
            "template": "Incident payload prepared. Title: {{ output.title }}"
        },# step 4
        {
            "name": "action",
            "parameters": {
                "action": "CreateIncident",
                "fields": {
                    "incident": {
                        "step": 4,
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
                    "incident_create": "step.4.output",
                    "rca": "step.2.output",
                },
            },
            "template": (
                "Status verdict for UpdateStatus: {{ output.verdict }} "
                "(FALSE_POSITIVE when incident create was a duplicate)."
            ),
        },# step 6
        {
            "name": "action",
            "parameters": {
                "action": "UpdateStatus",
                "fields": {
                    "id":{
                        "step": 0,
                        "path": "id"
                    },
                    "verdict":{
                        "step": 6,
                        "path": "output.verdict"
                    },
                    "detectiontime": {
                        "step": 0,
                        "path": "detectiontime",
                    },
                }
            },
            "template": "The alert status was modified in accordance with the verdict."
        }# step 7
    ]


def template():
    """
    RCA report for the detection UI — Palo Alto Authentication Monitor stream (HTML).

    Report bindings:
      - ``step_0``, ``step_1`` — outputs from each playbook step (0-based in template).
      - ``event`` — detection payload from playbook execution document.

    Variables mirror other Palo Alto RCAs: ``sessions`` from EventSession, ``event`` as fallback.
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
{%- set user_hint = (ev.get('user_name') or ev.get('user') or ev.get('username')) if ev is mapping else none -%}
{%- set user_hint = user_hint or ((_r0.get('user_name') or _r0.get('user') or _r0.get('username')) if _r0 is mapping else none) -%}
{%- set src_ip = (ev.get('source_ip') or ev.get('sourceip') or ev.get('src_ip') or ev.get('src')) if ev is mapping else none -%}
{%- set src_ip = src_ip or ((_r0.get('source_ip') or _r0.get('src_ip') or _r0.get('src') or _r0.get('sourceip')) if _r0 is mapping else none) -%}

{%- set inc_create = step_4|default({}, true) -%}
{%- set incident_dup_id = inc_create.get('incident_id') if inc_create is mapping else none -%}
{%- set resp = inc_create.get('responses') if inc_create is mapping else none -%}
{%- set inner_dup = resp.get(incident_dup_id) if resp is mapping and incident_dup_id else none -%}
{%- set is_incident_dup = (inc_create.get('duplicate') if inc_create is mapping else false) or (inner_dup is mapping and inner_dup.get('data') is mapping and inner_dup.get('data').get('duplicate')) -%}

<div class="rca-body">
  <section class="summary-strip">
    {%- if v == 'TRUE_POSITIVE' -%}
    <strong class="text-danger">Confirmed suspicious execution / persistence</strong>
    <p>The RCA completed successfully and found strong indicators consistent with malicious persistence or suspicious execution activity.</p>
    {%- elif v == 'SUSPICIOUS' -%}
    <strong class="text-warning">Suspicious activity</strong>
    <p>The RCA completed successfully and identified signals that warrant follow-up validation and correlation.</p>
    {%- elif v == 'FALSE_POSITIVE' -%}
    <strong>Likely benign / false positive</strong>
    <p>The RCA completed successfully, but the activity did not show strong enough signals to support a confirmed malicious event.</p>
    {%- else -%}
    <strong>RCA pending / unavailable</strong>
    <p>The RCA output is incomplete or pending. Review session evidence and rerun RCA if needed.</p>
    {%- endif -%}
  </section>

  <section class="card rca-block">
    <h2>Session Review</h2>
    <div class="body-copy">
      <p>Performed query to retrieve Windows execution and persistence-related session rows for RCA.</p>
      <span class="label">Outcome:</span>
      {%- if rows is not none and rows is iterable and rows is not string -%}
      <p>Rows returned: {{ rows|length }} event row(s){% if src_ip %} (source <strong>{{ src_ip }}</strong>){% endif %}.</p>
      {%- elif rows is not none -%}
      <p><strong>Result:</strong> present (non-list shape).</p>
      {%- else -%}
      <p>No session output in this run.</p>
      {%- endif -%}
    </div>
  </section>

  <section class="card rca-block">
    <h2>Execution &amp; Persistence Findings</h2>
    <div class="body-copy">
      <span class="label">Performed:</span>
      {%- if heuristics_html and heuristics_html|string and heuristics_html.strip() -%}
      <div>{{ heuristics_html }}</div>
      {%- else -%}
      <p>Evaluated new service installs (7045), scheduled task creation (4698), and suspicious process execution on domain controllers (1/7/10).</p>
      {%- endif -%}

      <span class="label">Outcome:</span>
      {%- if rca is mapping and rca.get('verdict') -%}
      <p>Verdict: <strong>{{ rca.get('verdict') }}</strong>{% if score is not none %} - aggregate score <strong>{{ score }}</strong>{% endif %}</p>
      {%- else -%}
      <p><em>RCA output not available.</em></p>
      {%- endif -%}

      {%- if artifacts is mapping -%}
      <span class="label">Artifacts used:</span>
      <div class="evidence-list">
        {%- if artifacts.get('service_install_events') is not none -%}
        <div class="evidence-row"><div class="evidence-key">Service installs</div><div class="evidence-value">{{ artifacts.get('service_install_events') }}</div></div>
        {%- endif -%}
        {%- if artifacts.get('scheduled_task_create_events') is not none -%}
        <div class="evidence-row"><div class="evidence-key">Scheduled tasks</div><div class="evidence-value">{{ artifacts.get('scheduled_task_create_events') }}</div></div>
        {%- endif -%}
        {%- if artifacts.get('dc_process_events') is not none -%}
        <div class="evidence-row"><div class="evidence-key">DC process events</div><div class="evidence-value">{{ artifacts.get('dc_process_events') }}</div></div>
        {%- endif -%}

        {%- if artifacts.get('service_name_samples') is iterable and artifacts.get('service_name_samples') is not string and artifacts.get('service_name_samples')|length > 0 -%}
        <div class="evidence-row"><div class="evidence-key">Service names</div><div class="evidence-value">{{ artifacts.get('service_name_samples')|join(', ')|e }}</div></div>
        {%- endif -%}
        {%- if artifacts.get('service_path_samples') is iterable and artifacts.get('service_path_samples') is not string and artifacts.get('service_path_samples')|length > 0 -%}
        <div class="evidence-row"><div class="evidence-key">Service paths</div><div class="evidence-value">{{ artifacts.get('service_path_samples')|join(', ')|e }}</div></div>
        {%- endif -%}
        {%- if artifacts.get('service_account_samples') is iterable and artifacts.get('service_account_samples') is not string and artifacts.get('service_account_samples')|length > 0 -%}
        <div class="evidence-row"><div class="evidence-key">Service accounts</div><div class="evidence-value">{{ artifacts.get('service_account_samples')|join(', ')|e }}</div></div>
        {%- endif -%}
        {%- if artifacts.get('service_installed_by_samples') is iterable and artifacts.get('service_installed_by_samples') is not string and artifacts.get('service_installed_by_samples')|length > 0 -%}
        <div class="evidence-row"><div class="evidence-key">Service installed-by</div><div class="evidence-value">{{ artifacts.get('service_installed_by_samples')|join(', ')|e }}</div></div>
        {%- endif -%}

        {%- if artifacts.get('task_name_samples') is iterable and artifacts.get('task_name_samples') is not string and artifacts.get('task_name_samples')|length > 0 -%}
        <div class="evidence-row"><div class="evidence-key">Task names</div><div class="evidence-value">{{ artifacts.get('task_name_samples')|join(', ')|e }}</div></div>
        {%- endif -%}
        {%- if artifacts.get('task_command_samples') is iterable and artifacts.get('task_command_samples') is not string and artifacts.get('task_command_samples')|length > 0 -%}
        <div class="evidence-row"><div class="evidence-key">Task commands</div><div class="evidence-value">{{ artifacts.get('task_command_samples')|join(', ')|e }}</div></div>
        {%- endif -%}
        {%- if artifacts.get('task_creator_samples') is iterable and artifacts.get('task_creator_samples') is not string and artifacts.get('task_creator_samples')|length > 0 -%}
        <div class="evidence-row"><div class="evidence-key">Task creators</div><div class="evidence-value">{{ artifacts.get('task_creator_samples')|join(', ')|e }}</div></div>
        {%- endif -%}
        {%- if artifacts.get('task_source_ip_samples') is iterable and artifacts.get('task_source_ip_samples') is not string and artifacts.get('task_source_ip_samples')|length > 0 -%}
        <div class="evidence-row"><div class="evidence-key">Task source IPs</div><div class="evidence-value">{{ artifacts.get('task_source_ip_samples')|join(', ')|e }}</div></div>
        {%- endif -%}

        {%- if artifacts.get('dc_process_name_samples') is iterable and artifacts.get('dc_process_name_samples') is not string and artifacts.get('dc_process_name_samples')|length > 0 -%}
        <div class="evidence-row"><div class="evidence-key">DC processes</div><div class="evidence-value">{{ artifacts.get('dc_process_name_samples')|join(', ')|e }}</div></div>
        {%- endif -%}
        {%- if artifacts.get('dc_host_samples') is iterable and artifacts.get('dc_host_samples') is not string and artifacts.get('dc_host_samples')|length > 0 -%}
        <div class="evidence-row"><div class="evidence-key">DC hosts</div><div class="evidence-value">{{ artifacts.get('dc_host_samples')|join(', ')|e }}</div></div>
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
    <p class="assessment-copy"><strong>Assessment:</strong> Findings support <span class="inline-verdict">confirmed suspicious execution/persistence</span>{% if score is not none %}. <strong>Score {{ score }}.</strong>{% endif %}</p>
    {%- elif v == 'SUSPICIOUS' -%}
    <p class="assessment-copy"><strong>Assessment:</strong> Findings are <span class="inline-verdict">suspicious</span> — validate change windows, admin activity, and correlate with endpoint/AD telemetry{% if score is not none %}. <strong>Score {{ score }}.</strong>{% endif %}</p>
    {%- elif v == 'FALSE_POSITIVE' -%}
    <p class="assessment-copy"><strong>Assessment:</strong> Treated as <span class="inline-verdict">false positive / likely benign</span> — no strong persistence or DC execution signal exceeded thresholds{% if score is not none %}. <strong>Score {{ score }}.</strong>{% endif %}</p>
    <p class="assessment-copy subtle-line"><strong>To fine-tune (baseline/whitelist), request customer context:</strong> {% if artifacts is mapping and artifacts.get('customer_context') %}{{ artifacts.get('customer_context') }}{% else %}confirm expected admin changes: planned software deployments, approved service installers, known scheduled tasks, and any maintenance window affecting DCs{% endif %}.</p>
    {%- else -%}
    <p class="assessment-copy"><strong>Assessment:</strong> Verdict is <strong>{{ v or 'pending or unavailable' }}</strong>{% if score is not none %}. <strong>Score {{ score }}.</strong>{% endif %}</p>
    {%- endif -%}
  </section>
</div>
<div class="rca-conclusion" data-rca-field="conclusion" style="display:none;">{{ conclusion_text }}</div>
</div>"""
