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
            "template": "EventSession completed — Network Traffic Anomaly session rows for RCA.",
        }, # step 1
        {
            "name": "execute_python_from_s3",
            "parameters": {
                "s3_path": "s3://automation/stream-root-cause-analysis/network_traffic_anomaly_detection/rca.py",
                "function_name": "run_rca",
                "variables": {
                    "sessions": "step.1.output",
                    "event": "event",
                },
            },
            "template": (
                "Traffic RCA: {{ output.verdict if output else 'n/a' }} "
                "(score {{ output.score if output else 'n/a' }})"
            ),
        }, # step 2
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
                "code": "def _row_count(x):\n    if isinstance(x, dict):\n        r = x.get('result')\n        if isinstance(r, list):\n            return len(r)\n        rows = x.get('rows')\n        if isinstance(rows, list):\n            return len(rows)\n        return 0\n    if isinstance(x, list):\n        return len(x)\n    return 0\n\nrca_out = rca if isinstance(rca, dict) else {}\nverdict = rca_out.get('verdict') or 'n/a'\nscore = rca_out.get('score')\nscore_text = str(score) if score is not None else 'n/a'\nrows = _row_count(sessions)\n\noutput = {\n  'title': f\"Network Traffic Anomaly RCA: {verdict} (score {score_text})\",\n  'description': (\n    f\"Analyzed {rows} network traffic session row(s) for anomalies (unusual outbound ports, inbound connection spikes, and abnormal traffic patterns). \"\n    f\"Result: {verdict} with aggregate score {score_text}.\"\n  )\n}\n",
                "variables": {
                    "sessions": "step.1.output",
                    "rca": "step.2.output",
                    "event": "event"
                }
            },
            "template": "Incident payload prepared. Title: {{ output.title }}"
        }, # step 4
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
        }, # step 5
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
        }, # step 6
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
        } # step 7
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
    <strong class="text-danger">Confirmed / high-risk anomaly</strong>
    <p>The RCA completed successfully and found strong indicators consistent with malicious or policy-violating network traffic.</p>
    {%- elif v == 'SUSPICIOUS' -%}
    <strong class="text-warning">Suspicious activity</strong>
    <p>The RCA completed successfully and identified signals that warrant follow-up validation and correlation.</p>
    {%- elif v == 'FALSE_POSITIVE' -%}
    <strong>Likely benign / false positive</strong>
    <p>The RCA completed successfully, but the traffic pattern did not show strong enough signals to support a confirmed malicious event.</p>
    {%- else -%}
    <strong>RCA pending / unavailable</strong>
    <p>The RCA output is incomplete or pending. Review session evidence and rerun RCA if needed.</p>
    {%- endif -%}
  </section>

  <section class="card rca-block">
    <h2>Session Review</h2>
    <div class="body-copy">
      <p>Performed query to retrieve network traffic session rows for anomaly analysis.</p>
      <span class="label">Outcome:</span>
      {%- if rows is not none and rows is iterable and rows is not string -%}
      <p>Rows returned: {{ rows|length }} flow row(s){% if src_ip or user_hint %} ({% if src_ip %}source <strong>{{ src_ip }}</strong>{% endif %}{% if src_ip and user_hint %}, {% endif %}{% if user_hint %}user <strong>{{ user_hint }}</strong>{% endif %}){% endif %}.</p>
      {%- elif rows is not none -%}
      <p><strong>Result:</strong> present (non-list shape).</p>
      {%- else -%}
      <p>No session output in this run.</p>
      {%- endif -%}
    </div>
  </section>

  <section class="card rca-block">
    <h2>Traffic Findings</h2>
    <div class="body-copy">
      <span class="label">Performed:</span>
      {%- if heuristics_html and heuristics_html|string and heuristics_html.strip() -%}
      <div>{{ heuristics_html }}</div>
      {%- else -%}
      <p>Evaluated unusual outbound ports and inbound connection spikes.</p>
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
        {%- if artifacts.get('traffic_rows') is not none -%}
        <div class="evidence-row">
          <div class="evidence-key">Traffic rows</div>
          <div class="evidence-value">{{ artifacts.get('traffic_rows') }} analyzed</div>
        </div>
        {%- endif -%}

        {%- if artifacts.get('unique_network_protocols') is iterable and artifacts.get('unique_network_protocols') is not string and artifacts.get('unique_network_protocols')|length > 0 -%}
        <div class="evidence-row">
          <div class="evidence-key">Protocols</div>
          <div class="evidence-value">
            {%- for p in artifacts.get('unique_network_protocols')[:3] -%}
            {{ p }}{% if not loop.last %}, {% endif %}
            {%- endfor -%}
            {%- if artifacts.get('unique_network_protocols')|length > 3 -%}
            <span style="color: rgba(239, 243, 255, 0.56);" title="{{ artifacts.get('unique_network_protocols')|join(', ')|e }}">(+{{ artifacts.get('unique_network_protocols')|length - 3 }} more)</span>
            {%- endif -%}
          </div>
        </div>
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
        <div class="evidence-row">
          <div class="evidence-key">Source</div>
          <div class="evidence-value">{{ artifacts.get('sample_source_ip') }}</div>
        </div>
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
        <div class="evidence-row">
          <div class="evidence-key">Destination</div>
          <div class="evidence-value">{{ artifacts.get('sample_destination_ip') }}</div>
        </div>
        {%- endif -%}

        {%- if artifacts.get('unique_destination_ports') is iterable and artifacts.get('unique_destination_ports') is not string and artifacts.get('unique_destination_ports')|length > 0 -%}
        <div class="evidence-row">
          <div class="evidence-key">Ports</div>
          <div class="evidence-value">
            {%- for p in artifacts.get('unique_destination_ports')[:3] -%}
            {{ p }}{% if not loop.last %}, {% endif %}
            {%- endfor -%}
            {%- if artifacts.get('unique_destination_ports')|length > 3 -%}
            <span style="color: rgba(239, 243, 255, 0.56);" title="{{ artifacts.get('unique_destination_ports')|join(', ')|e }}">(+{{ artifacts.get('unique_destination_ports')|length - 3 }} more)</span>
            {%- endif -%}
          </div>
        </div>
        {%- elif artifacts.get('sample_destination_port') -%}
        <div class="evidence-row">
          <div class="evidence-key">Port</div>
          <div class="evidence-value">{{ artifacts.get('sample_destination_port') }}</div>
        </div>
        {%- endif -%}

        {%- if artifacts.get('unique_source_device_names') is iterable and artifacts.get('unique_source_device_names') is not string and artifacts.get('unique_source_device_names')|length > 0 -%}
        <div class="evidence-row">
          <div class="evidence-key">Source device</div>
          <div class="evidence-value">
            {%- for h in artifacts.get('unique_source_device_names')[:3] -%}
            {{ h }}{% if not loop.last %}, {% endif %}
            {%- endfor -%}
            {%- if artifacts.get('unique_source_device_names')|length > 3 -%}
            <span style="color: rgba(239, 243, 255, 0.56);" title="{{ artifacts.get('unique_source_device_names')|join(', ')|e }}">(+{{ artifacts.get('unique_source_device_names')|length - 3 }} more)</span>
            {%- endif -%}
          </div>
        </div>
        {%- elif artifacts.get('sample_source_device_name') -%}
        <div class="evidence-row">
          <div class="evidence-key">Source device</div>
          <div class="evidence-value">{{ artifacts.get('sample_source_device_name') }}</div>
        </div>
        {%- endif -%}

        {%- if artifacts.get('unique_event_actions') is iterable and artifacts.get('unique_event_actions') is not string and artifacts.get('unique_event_actions')|length > 0 -%}
        <div class="evidence-row">
          <div class="evidence-key">Event actions</div>
          <div class="evidence-value">
            {%- for a in artifacts.get('unique_event_actions')[:3] -%}
            {{ a }}{% if not loop.last %}, {% endif %}
            {%- endfor -%}
            {%- if artifacts.get('unique_event_actions')|length > 3 -%}
            <span style="color: rgba(239, 243, 255, 0.56);" title="{{ artifacts.get('unique_event_actions')|join(', ')|e }}">(+{{ artifacts.get('unique_event_actions')|length - 3 }} more)</span>
            {%- endif -%}
          </div>
        </div>
        {%- elif artifacts.get('sample_event_action') -%}
        <div class="evidence-row">
          <div class="evidence-key">Event action</div>
          <div class="evidence-value">{{ artifacts.get('sample_event_action') }}</div>
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
    <p class="assessment-copy"><strong>Assessment:</strong> Network traffic patterns strongly indicate <span class="inline-verdict">malicious or policy-violating activity</span>{% if score is not none %}. <strong>Score {{ score }}.</strong>{% endif %}</p>
    {%- elif v == 'SUSPICIOUS' -%}
    <p class="assessment-copy"><strong>Assessment:</strong> Findings are <span class="inline-verdict">suspicious</span> — validate destinations, ports, assets, and recent changes before closing{% if score is not none %}. <strong>Score {{ score }}.</strong>{% endif %}</p>
    {%- elif v == 'FALSE_POSITIVE' -%}
    <p class="assessment-copy"><strong>Assessment:</strong> Treated as <span class="inline-verdict">false positive / likely benign</span> — no significant network anomaly exceeded configured thresholds{% if score is not none %}. <strong>Score {{ score }}.</strong>{% endif %}</p>
    <p class="assessment-copy subtle-line"><strong>To fine-tune (baseline/whitelist), request customer context:</strong> {% if artifacts is mapping and artifacts.get('customer_context') %}{{ artifacts.get('customer_context') }}{% else %}asset role/owner, expected application/service, approved destinations/ports, and whether the observed sources/destinations are known or sanctioned{% endif %}.</p>
    {%- else -%}
    <p class="assessment-copy"><strong>Assessment:</strong> Verdict is <strong>{{ v or 'pending or unavailable' }}</strong>{% if score is not none %}. <strong>Score {{ score }}.</strong>{% endif %}</p>
    {%- endif -%}
  </section>
</div>
<div class="rca-conclusion" data-rca-field="conclusion" style="display:none;">{{ conclusion_text }}</div>
</div>"""
  
