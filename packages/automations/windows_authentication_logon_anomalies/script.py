"""
Sample automation: EventSession → run_rca (MinIO script) — Authentication Logon Anomalies.

Upload to MinIO:
  bucket: automation
  key: stream-root-cause-analysis/authentication_logon_anomalies/rca.py
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
                "logon-related event row(s) for RCA. "
                "Purpose: gather authentication evidence to evaluate anomalous logon patterns and suspicious access behavior."
            ),
        },# step 1
        {
            "name": "execute_python_from_s3",
            "parameters": {
                "s3_path": "s3://automation/stream-root-cause-analysis/authentication_logon_anomalies/rca.py",
                "function_name": "run_rca",
                "variables": {
                    "sessions": "step.1.output",
                    "event": "event",
                },
            },
            "template": (
                "Authentication Logon Anomalies RCA completed: "
                "{{ output.verdict if output else 'n/a' }} "
                "(score {{ output.score if output else 'n/a' }}). "
                "Heuristics executed: logon anomaly detection across sampled authentication events."
            ),
        },# step 2
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
        },# step 3
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
                    "\n"
                    "user = arts.get('sample_user') or (arts.get('unique_users') or [None])[0]\n"
                    "src = arts.get('sample_source_ip') or (arts.get('unique_source_ips') or [None])[0]\n"
                    "\n"
                    "title_bits = [f\"Authentication Logon Anomalies RCA: {verdict} (score {score_text})\"]\n"
                    "if user:\n"
                    "    title_bits.append(f\"user={user}\")\n"
                    "if src:\n"
                    "    title_bits.append(f\"src={src}\")\n"
                    "\n"
                    "output = {\n"
                    "  'title': ' | '.join(title_bits),\n"
                    "  'description': (\n"
                    "    f\"Analyzed {rows} authentication/logon row(s) for brute force, password spraying, success-after-failure, excessive RDP, and multi-host logons. \"\n"
                    "    f\"Result: {verdict} with aggregate score {score_text}. \"\n"
                    "    f\"Evidence: user={user or 'n/a'}, src={src or 'n/a'}.\"\n"
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
        },# step 4
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
        },# step 7
    ]


def template():
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

{%- set inc_create = step_4|default({}, true) -%}
{%- set incident_dup_id = inc_create.get('incident_id') if inc_create is mapping else none -%}
{%- set resp = inc_create.get('responses') if inc_create is mapping else none -%}
{%- set inner_dup = resp.get(incident_dup_id) if resp is mapping and incident_dup_id else none -%}
{%- set is_incident_dup = (inc_create.get('duplicate') if inc_create is mapping else false) or (inner_dup is mapping and inner_dup.get('data') is mapping and inner_dup.get('data').get('duplicate')) -%}

<div class="rca-body">
  <section class="summary-strip">
    {%- if v == 'TRUE_POSITIVE' -%}
    <strong class="text-danger">Confirmed / high-risk authentication anomaly</strong>
    <p>The RCA completed successfully and found strong indicators consistent with brute force, password spraying, or credential compromise.</p>
    {%- elif v == 'SUSPICIOUS' -%}
    <strong class="text-warning">Suspicious authentication activity</strong>
    <p>The RCA completed successfully and identified signals that warrant follow-up validation and correlation.</p>
    {%- elif v == 'LOW_RISK' -%}
    <strong>Likely low-risk anomaly</strong>
    <p>The RCA completed successfully; weak signals were observed. Validate user/source context before closing.</p>
    {%- elif v == 'FALSE_POSITIVE' -%}
    <strong>Likely benign / false positive</strong>
    <p>The RCA completed successfully, but the analyzed evidence did not support a confirmed malicious authentication event.</p>
    {%- else -%}
    <strong>RCA pending / unavailable</strong>
    <p>The RCA output is incomplete or pending. Review event/session evidence and rerun RCA if needed.</p>
    {%- endif -%}
  </section>

  <section class="card rca-block">
    <h2>Session Review</h2>
    <div class="body-copy">
      <p>Performed query to retrieve authentication/logon rows for anomaly analysis.</p>
      <span class="label">Outcome:</span>
      {%- if rows is not none and rows is iterable and rows is not string -%}
      <p>Rows returned: {{ rows|length }} event row(s).</p>
      {%- elif rows is not none -%}
      <p><strong>Result:</strong> present (non-list shape).</p>
      {%- else -%}
      <p>No session output in this run.</p>
      {%- endif -%}
    </div>
  </section>

  <section class="card rca-block">
    <h2>Authentication Findings</h2>
    <div class="body-copy">
      <span class="label">Performed:</span>
      {%- if heuristics_html and heuristics_html|string and heuristics_html.strip() -%}
      <div>{{ heuristics_html }}</div>
      {%- else -%}
      <p>Evaluated brute force, password spraying, success-after-failure, excessive RDP, and multi-host logon behavior.</p>
      {%- endif -%}

      <span class="label">Outcome:</span>
      {%- if rca is mapping and rca.get('verdict') -%}
      <p>Verdict: <strong>{{ rca.get('verdict') }}</strong>{% if score is not none %} - aggregate score <strong>{{ score }}</strong>{% endif %}</p>
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

        {%- if artifacts.get('unique_users') is iterable and artifacts.get('unique_users') is not string and artifacts.get('unique_users')|length > 0 -%}
        <div class="evidence-row"><div class="evidence-key">Users</div><div class="evidence-value">{{ artifacts.get('unique_users')[:3]|join(', ')|e }}{% if artifacts.get('unique_users')|length > 3 %} <span style="color: rgba(239, 243, 255, 0.56);" title="{{ artifacts.get('unique_users')|join(', ')|e }}">(+{{ artifacts.get('unique_users')|length - 3 }} more)</span>{% endif %}</div></div>
        {%- endif -%}

        {%- if artifacts.get('unique_source_ips') is iterable and artifacts.get('unique_source_ips') is not string and artifacts.get('unique_source_ips')|length > 0 -%}
        <div class="evidence-row"><div class="evidence-key">Source IPs</div><div class="evidence-value">{{ artifacts.get('unique_source_ips')[:3]|join(', ')|e }}{% if artifacts.get('unique_source_ips')|length > 3 %} <span style="color: rgba(239, 243, 255, 0.56);" title="{{ artifacts.get('unique_source_ips')|join(', ')|e }}">(+{{ artifacts.get('unique_source_ips')|length - 3 }} more)</span>{% endif %}</div></div>
        {%- endif -%}

        {%- if artifacts.get('unique_destination_hosts') is iterable and artifacts.get('unique_destination_hosts') is not string and artifacts.get('unique_destination_hosts')|length > 0 -%}
        <div class="evidence-row"><div class="evidence-key">Hosts</div><div class="evidence-value">{{ artifacts.get('unique_destination_hosts')[:3]|join(', ')|e }}{% if artifacts.get('unique_destination_hosts')|length > 3 %} <span style="color: rgba(239, 243, 255, 0.56);" title="{{ artifacts.get('unique_destination_hosts')|join(', ')|e }}">(+{{ artifacts.get('unique_destination_hosts')|length - 3 }} more)</span>{% endif %}</div></div>
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
    <p class="assessment-copy"><strong>Assessment:</strong> Confirmed malicious or high-risk authentication activity was identified. Immediate investigation and containment is recommended{% if score is not none %}. <strong>Score {{ score }}.</strong>{% endif %}</p>
    {%- elif v == 'SUSPICIOUS' -%}
    <p class="assessment-copy"><strong>Assessment:</strong> Suspicious indicators were observed. Validate business context, correlate telemetry, and confirm whether the activity is legitimate{% if score is not none %}. <strong>Score {{ score }}.</strong>{% endif %}</p>
    {%- elif v == 'LOW_RISK' -%}
    <p class="assessment-copy"><strong>Assessment:</strong> Low-risk signals were observed. Validate user/source context and recent maintenance/testing before closing{% if score is not none %}. <strong>Score {{ score }}.</strong>{% endif %}</p>
    {%- elif v == 'FALSE_POSITIVE' -%}
    <p class="assessment-copy"><strong>Assessment:</strong> No meaningful malicious indicators were identified. Based on the available evidence, the alert is likely benign or false positive noise{% if score is not none %}. <strong>Score {{ score }}.</strong>{% endif %}</p>
    <p class="assessment-copy subtle-line"><strong>To fine-tune (baseline/whitelist), request customer context:</strong> {% if artifacts is mapping and artifacts.get('customer_context') %}{{ artifacts.get('customer_context') }}{% else %}confirm expected sources (VPN/jump hosts), service accounts, MFA/lockout policy, and whether the activity matches planned testing{% endif %}.</p>
    {%- else -%}
    <p class="assessment-copy"><strong>Assessment:</strong> Verdict is <strong>{{ v or 'pending or unavailable' }}</strong>{% if score is not none %}. <strong>Score {{ score }}.</strong>{% endif %}</p>
    {%- endif -%}
  </section>
</div>
<div class="rca-conclusion" data-rca-field="conclusion" style="display:none;">{{ conclusion_text }}</div>
</div>"""