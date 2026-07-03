"""
Sample automation: EventSession → threatlab tool (AbuseIPDB) → run_rca (MinIO script).

Upload to MinIO:
  bucket: automation
  key: stream-root-cause-analysis/palo_alto_threat_intelligence/rca.py

Requires API_ENDPOINT pointing at incident-management playbook base (e.g. http://incident-management-service:9019/tool) so threatlab calls /tool/threatlab/execute.

Adjust step 2 `input.ip` path to match your EventSession output (columns/rows vs result list).
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
                        "path": "event"
                    }
                }
            },
            "template": "EventSession: retrieved "
                "{{ (output.result|length if output is mapping and output.result is iterable and output.result is not string else (output.rows|length if output is mapping and output.rows is iterable and output.rows is not string else (output|length if output is iterable and output is not string else 'n/a'))) }} "
                "VPN session row(s) for RCA. "
                "Gathered VPN authentication and access evidence for impossible travel, repeated failures, and risky sources."
        }, #step 1

        {
            "name": "execute_python_from_s3",
            "parameters": {
                "s3_path": "s3://automation/stream-root-cause-analysis/utils/extract_distinct_ips.py",
                "function_name": "extract_distinct_ips",
                "variables": {
                    "sessions": "step.1.output"
                }
            },
            "template": "Extracted distinct source IP(s) for enrichment: "
                "{{ output|length if output is iterable and output is not string else 'n/a' }} unique IP(s)."
        }, #step 2

        {
            "name": "threatlab",
            "parameters": {
                "threat_intel_id": "threatintel.abuseipdb.lookup_ip",
                "input": {
                    "ip": "step.2.output",
                    "days": 90,
                    "verbose": "yes"
                }
            },
            "template": "AbuseIPDB enrichment executed for source IP reputation "
                "(fan-out supported when an IP list is provided)."
        }, #step 3

        {
            "name": "execute_python_from_s3",
            "parameters": {
                "s3_path": "s3://automation/stream-root-cause-analysis/vpn_security_monitoring/rca.py",
                "function_name": "run_rca",
                "variables": {
                    "sessions": "step.1.output",
                    "event": "event",
                    "threatlab_execute": "step.3.output"
                }
            },
            "template": (
                "VPN Security Monitoring RCA completed: "
                "{{ output.verdict if output else 'n/a' }} "
                "(score {{ output.score if output else 'n/a' }}). "
                "Heuristics executed: impossible travel indicators, repeated VPN authentication failures, "
                "and AbuseIPDB-based source IP reputation context when available."
            )
        }, #step 4
        {
            "name": "evaluate",
            "parameters": {
                "step": 4,
                "condition": "output.verdict == 'TRUE_POSITIVE'",
                "if_step": 6,
                "else_step": 8
            },
            "template": "Evaluated the RCA verdict to decide whether to create an incident."
        }, #step 5
        {
            "name": "execute_python",
            "parameters": {
                "code": "def _row_count(x):\n    if isinstance(x, dict):\n        r = x.get('result')\n        if isinstance(r, list):\n            return len(r)\n        rows = x.get('rows')\n        if isinstance(rows, list):\n            return len(rows)\n        return 0\n    if isinstance(x, list):\n        return len(x)\n    return 0\n\nrca_out = rca if isinstance(rca, dict) else {}\nverdict = rca_out.get('verdict') or 'n/a'\nscore = rca_out.get('score')\nscore_text = str(score) if score is not None else 'n/a'\nrows = _row_count(sessions)\nip_count = len(ips) if isinstance(ips, list) else 0\n\noutput = {\n  'title': f\"FortiGate VPN Security Monitoring RCA: {verdict} (score {score_text})\",\n  'description': (\n    f\"Analyzed {rows} VPN session row(s) for impossible travel indicators and repeated authentication failures, enriched across {ip_count} source IP(s) using AbuseIPDB when available. \"\n    f\"Result: {verdict} with aggregate score {score_text}.\"\n  )\n}\n",
                "variables": {
                    "sessions": "step.1.output",
                    "ips": "step.2.output",
                    "rca": "step.4.output",
                    "event": "event"
                }
            },
            "template": "Incident payload prepared. Title: {{ output.title }}"
        },#step 6
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
              "{{ inner.result if inner and inner.result is defined else output.incident_id }}"
          ),
        }, #step 7
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
                    "rca": "step.4.output",
                },
            },
            "template": (
                "Status verdict for UpdateStatus: {{ output.verdict }} "
                "(FALSE_POSITIVE when incident create was a duplicate)."
            ),
        }, #step 8
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
        } #step 9
    ]


def template():
    """
    RCA report for the detection UI — FortiGate VPN Security Monitoring stream (HTML).

    Report bindings (see ``report_generation.process_message_report``):
      - ``step_0`` … ``step_n`` — outputs from each playbook step (0-based).
      - ``event`` — detection payload from the playbook execution document, same
        object passed as ``event`` in steps.
    """
    # Jinja emits newlines around {% %} by default — use {%- -%} so the UI does not show huge gaps
    # (plain LLM text has no Jinja noise). Root sets white-space: normal to override parent pre-wrap.
    return """<div class="rca-report" style="font-family:system-ui,Segoe UI,sans-serif;line-height:1.45;white-space:normal;">

{%- set s1 = step_0|default({}, true) -%}
{%- set extracted_ips = step_1|default([], true) -%}
{%- set s2 = step_2|default({}, true) -%}
{%- set rca = step_3|default({}, true) -%}
{%- set ev = event|default({}, true) -%}
{%- set v = rca.get('verdict') -%}
{%- set score = rca.get('score') -%}
{%- set reason_text = rca.get('reason', '') -%}
{%- set conclusion_text = rca.get('conclusion', '') -%}
{%- set heuristics_html = rca.get('heuristics', '') -%}
{%- set artifacts = rca.get('artifacts') if rca is mapping else none -%}
{%- set rows = (s1.get('result') if s1 is mapping else (s1 if s1 is iterable and s1 is not string else none)) -%}
{%- set _r0 = rows[0] if rows is not none and rows is iterable and rows is not string and rows|length > 0 else none -%}

{%- set inc_create = step_7|default({}, true) -%}
{%- set incident_dup_id = inc_create.get('incident_id') if inc_create is mapping else none -%}
{%- set resp = inc_create.get('responses') if inc_create is mapping else none -%}
{%- set inner_dup = resp.get(incident_dup_id) if resp is mapping and incident_dup_id else none -%}
{%- set is_incident_dup = (inc_create.get('duplicate') if inc_create is mapping else false) or (inner_dup is mapping and inner_dup.get('data') is mapping and inner_dup.get('data').get('duplicate')) -%}

<div class="rca-body">
  <section class="summary-strip">
    {%- if v == 'TRUE_POSITIVE' -%}
    <strong class="text-danger">Confirmed / high-risk VPN activity</strong>
    <p>The RCA completed successfully and found strong indicators consistent with suspicious or malicious VPN access.</p>
    {%- elif v == 'SUSPICIOUS' -%}
    <strong class="text-warning">Suspicious activity</strong>
    <p>The RCA completed successfully and identified signals that warrant follow-up validation and correlation.</p>
    {%- elif v == 'FALSE_POSITIVE' -%}
    <strong>Likely benign / false positive</strong>
    <p>The RCA completed successfully, but the VPN activity did not show strong enough signals to support a confirmed malicious event.</p>
    {%- else -%}
    <strong>RCA pending / unavailable</strong>
    <p>The RCA output is incomplete or pending. Review session evidence and rerun RCA if needed.</p>
    {%- endif -%}
  </section>

  <section class="card rca-block">
    <h2>Session Review</h2>
    <div class="body-copy">
      <p>Performed query to retrieve VPN session rows for RCA.</p>
      <span class="label">Outcome:</span>
      {%- if rows is not none and rows is iterable and rows is not string -%}
      <p>Rows returned: {{ rows|length }} session row(s).</p>
      {%- elif rows is not none -%}
      <p><strong>Result:</strong> present (non-list shape).</p>
      {%- else -%}
      <p>No session output in this run.</p>
      {%- endif -%}
      {%- if extracted_ips is iterable and extracted_ips is not string -%}
      <p style="margin:.35rem 0 0 0;"><strong>Unique source IPs extracted for TI:</strong> {{ extracted_ips|length }}{% if extracted_ips|length > 0 %} (sample <strong title="{{ extracted_ips|join(', ')|e }}">{{ extracted_ips[0] }}</strong>){% endif %}</p>
      {%- endif -%}
    </div>
  </section>

  <section class="card rca-block">
    <h2>VPN Findings</h2>
    <div class="body-copy">
      <span class="label">Performed:</span>
      {%- if heuristics_html and heuristics_html|string and heuristics_html.strip() -%}
      <div><strong>VPN RCA:</strong> {{ heuristics_html }}</div>
      {%- else -%}
      <p>Evaluated impossible travel, repeated login failures, and source IP reputation (AbuseIPDB when available).</p>
      {%- endif -%}

      <span class="label">Threat intelligence:</span>
      <div class="evidence-list">
        {%- if artifacts is mapping and artifacts.get('threatlab_used') and artifacts.get('threatlab_ip_reputations') is iterable and artifacts.get('threatlab_ip_reputations') is not string and artifacts.get('threatlab_ip_reputations')|length > 0 -%}
        {%- set reps = artifacts.get('threatlab_ip_reputations') -%}
        <div class="evidence-row">
          <div class="evidence-key">AbuseIPDB lookups</div>
          <div class="evidence-value">{{ reps|length }} (max score {{ artifacts.get('threatlab_max_risk_score', 0) }})</div>
        </div>
        {%- set _f = reps[0] if reps|length > 0 else none -%}
        {%- if _f is mapping and _f.get('ip') -%}
        <div class="evidence-row">
          <div class="evidence-key">Example</div>
          <div class="evidence-value">{{ _f.get('ip') }} (score {{ _f.get('risk_score') }}{% if _f.get('totalReports') is not none %}, reports {{ _f.get('totalReports') }}{% endif %})</div>
        </div>
        {%- endif -%}
        {%- elif artifacts is mapping and artifacts.get('threatlab_used') -%}
        <div class="evidence-row"><div class="evidence-key">AbuseIPDB</div><div class="evidence-value">Executed (no per-IP reputation list attached)</div></div>
        {%- else -%}
        <div class="evidence-row"><div class="evidence-key">AbuseIPDB</div><div class="evidence-value">Not available for this run</div></div>
        {%- endif -%}
      </div>

      <span class="label">Outcome:</span>
      {%- if rca is mapping and rca.get('verdict') -%}
      <p>Verdict: <strong>{{ rca.get('verdict') }}</strong>{% if score is not none %} - aggregate score <strong>{{ score }}</strong>{% endif %}</p>
      {%- else -%}
      <p><em>RCA output not available.</em></p>
      {%- endif -%}

      {%- if artifacts is mapping -%}
      <span class="label">Artifacts used:</span>
      <div class="evidence-list">
        {%- if artifacts.get('vpn_logs') is not none -%}
        <div class="evidence-row"><div class="evidence-key">VPN logs</div><div class="evidence-value">{{ artifacts.get('vpn_logs') }} analyzed</div></div>
        {%- endif -%}

        {%- if artifacts.get('unique_usernames') is iterable and artifacts.get('unique_usernames') is not string and artifacts.get('unique_usernames')|length > 0 -%}
        <div class="evidence-row">
          <div class="evidence-key">Users</div>
          <div class="evidence-value">
            {%- for u in artifacts.get('unique_usernames')[:3] -%}
            {{ u }}{% if not loop.last %}, {% endif %}
            {%- endfor -%}
            {%- if artifacts.get('unique_usernames')|length > 3 -%}
            <span style="color: rgba(239, 243, 255, 0.56);" title="{{ artifacts.get('unique_usernames')|join(', ')|e }}">(+{{ artifacts.get('unique_usernames')|length - 3 }} more)</span>
            {%- endif -%}
          </div>
        </div>
        {%- elif artifacts.get('sample_user') -%}
        <div class="evidence-row"><div class="evidence-key">User</div><div class="evidence-value">{{ artifacts.get('sample_user') }}</div></div>
        {%- endif -%}

        {%- if artifacts.get('unique_source_ips') is iterable and artifacts.get('unique_source_ips') is not string and artifacts.get('unique_source_ips')|length > 0 -%}
        <div class="evidence-row">
          <div class="evidence-key">Sources</div>
          <div class="evidence-value">
            {%- for s in artifacts.get('unique_source_ips')[:3] -%}
            {{ s }}{% if not loop.last %}, {% endif %}
            {%- endfor -%}
            {%- if artifacts.get('unique_source_ips')|length > 3 -%}
            <span style="color: rgba(239, 243, 255, 0.56);" title="{{ artifacts.get('unique_source_ips')|join(', ')|e }}">(+{{ artifacts.get('unique_source_ips')|length - 3 }} more)</span>
            {%- endif -%}
          </div>
        </div>
        {%- elif artifacts.get('sample_source_ip') -%}
        <div class="evidence-row"><div class="evidence-key">Source</div><div class="evidence-value">{{ artifacts.get('sample_source_ip') }}</div></div>
        {%- endif -%}

        {%- if artifacts.get('unique_destination_ips') is iterable and artifacts.get('unique_destination_ips') is not string and artifacts.get('unique_destination_ips')|length > 0 -%}
        <div class="evidence-row">
          <div class="evidence-key">Destinations</div>
          <div class="evidence-value">
            {%- for d in artifacts.get('unique_destination_ips')[:3] -%}
            {{ d }}{% if not loop.last %}, {% endif %}
            {%- endfor -%}
            {%- if artifacts.get('unique_destination_ips')|length > 3 -%}
            <span style="color: rgba(239, 243, 255, 0.56);" title="{{ artifacts.get('unique_destination_ips')|join(', ')|e }}">(+{{ artifacts.get('unique_destination_ips')|length - 3 }} more)</span>
            {%- endif -%}
          </div>
        </div>
        {%- elif artifacts.get('sample_destination_ip') -%}
        <div class="evidence-row"><div class="evidence-key">Destination</div><div class="evidence-value">{{ artifacts.get('sample_destination_ip') }}</div></div>
        {%- endif -%}

        {%- if artifacts.get('top_failed_login_sources') is iterable and artifacts.get('top_failed_login_sources') is not string and artifacts.get('top_failed_login_sources')|length > 0 -%}
        <div class="evidence-row">
          <div class="evidence-key">Failed-login sources</div>
          <div class="evidence-value">
            {%- for it in artifacts.get('top_failed_login_sources')[:3] -%}
              {%- if it is mapping -%}
              {{ it.get('ip') }}={{ it.get('failures') }}{% if not loop.last %}, {% endif %}
              {%- endif -%}
            {%- endfor -%}
            {%- if artifacts.get('top_failed_login_sources')|length > 3 -%}
            <span style="color: rgba(239, 243, 255, 0.56);" title="{% for it in artifacts.get('top_failed_login_sources') %}{% if it is mapping %}{{ it.get('ip') }}={{ it.get('failures') }}{% if not loop.last %}, {% endif %}{% endif %}{% endfor %}">(+{{ artifacts.get('top_failed_login_sources')|length - 3 }} more)</span>
            {%- endif -%}
          </div>
        </div>
        {%- endif -%}

        {%- if artifacts.get('impossible_travel_users') is mapping and artifacts.get('impossible_travel_users')|length > 0 -%}
        <div class="evidence-row"><div class="evidence-key">Impossible-travel users</div><div class="evidence-value">{{ artifacts.get('impossible_travel_users')|length }}</div></div>
        {%- endif -%}

        {%- if artifacts.get('high_risk_source_ips') is iterable and artifacts.get('high_risk_source_ips') is not string and artifacts.get('high_risk_source_ips')|length > 0 -%}
        <div class="evidence-row">
          <div class="evidence-key">High-risk IPs</div>
          <div class="evidence-value">
            {%- for h in artifacts.get('high_risk_source_ips')[:3] -%}
              {%- if h is mapping -%}
              {{ h.get('ip') }} ({{ h.get('risk_score') }}){% if not loop.last %}, {% endif %}
              {%- endif -%}
            {%- endfor -%}
            {%- if artifacts.get('high_risk_source_ips')|length > 3 -%}
            <span style="color: rgba(239, 243, 255, 0.56);" title="{% for h in artifacts.get('high_risk_source_ips') %}{% if h is mapping %}{{ h.get('ip') }} ({{ h.get('risk_score') }}){% if not loop.last %}, {% endif %}{% endif %}{% endfor %}">(+{{ artifacts.get('high_risk_source_ips')|length - 3 }} more)</span>
            {%- endif -%}
          </div>
        </div>
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
    <p class="assessment-copy"><strong>Assessment:</strong> Classified as <span class="inline-verdict">confirmed malicious or high-fidelity threat activity</span>{% if score is not none %}. <strong>Score {{ score }}.</strong>{% endif %}</p>
    {%- elif v == 'SUSPICIOUS' -%}
    <p class="assessment-copy"><strong>Assessment:</strong> Findings are <span class="inline-verdict">suspicious</span> — correlate with MFA/device posture and customer travel context{% if score is not none %}. <strong>Score {{ score }}.</strong>{% endif %}</p>
    {%- elif v == 'FALSE_POSITIVE' -%}
    <p class="assessment-copy"><strong>Assessment:</strong> Treated as <span class="inline-verdict">false positive / likely benign</span> — no strong threat signal from the analyzed sessions{% if score is not none %}. <strong>Score {{ score }}.</strong>{% endif %}</p>
    <p class="assessment-copy subtle-line"><strong>To fine-tune (baseline/whitelist), request customer context:</strong> {% if artifacts is mapping and artifacts.get('customer_context') %}{{ artifacts.get('customer_context') }}{% else %}request expected travel, approved VPN regions/IPs, known device/user, and use artifacts to baseline unique users/IPs{% endif %}.</p>
    {%- else -%}
    <p class="assessment-copy"><strong>Assessment:</strong> Verdict is <strong>{{ v or 'pending or unavailable' }}</strong>{% if score is not none %}. <strong>Score {{ score }}.</strong>{% endif %}</p>
    {%- endif -%}
  </section>
</div>
<div class="rca-conclusion" data-rca-field="conclusion" style="display:none;">{{ conclusion_text }}</div>
</div>"""
