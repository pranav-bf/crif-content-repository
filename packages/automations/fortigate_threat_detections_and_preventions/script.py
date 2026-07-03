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
        # STEP 1 — SESSION
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
                "threat-detection session row(s) for RCA. "
                "Gathered detection/prevention evidence to validate alert fidelity and supporting telemetry."
        },

        # STEP 2 — EXTRACT ARTIFACTS (URL extraction)
        {
            "name": "execute_python_from_s3",
            "parameters": {
                "s3_path": "s3://automation/stream-root-cause-analysis/threat_detections_and_preventions/rca.py",
                "function_name": "extract_artifacts",
                "variables": {
                "sessions": "step.1.output",
                "events": "event"
            },
            },
            "template": "Extracted artifacts including URLs for enrichment."
        },

        # STEP 3 — VIRUSTOTAL URL CHECK
        {
            "name": "threatlab",
            "parameters": {
                "threat_intel_id": "threatintel.virustotalv3.url_reputation",
                "input": {
                    "url": "step.2.output.urls"
                }
            },
            "template": "VirusTotal URL reputation enrichment executed for extracted URLs."
        },
                # STEP 4 - ABUSEIPDB DESTINATION IP CHECK
        {
            "name": "threatlab",
            "parameters": {
                "threat_intel_id": "threatintel.abuseipdb.lookup_ip",
                "input": {
                    # List fan-out supported: executor calls AbuseIPDB once per IP.
                    "ip": "step.2.output.unique_destination_ips",
                    "days": 90,
                    "verbose": "yes"
                }
            },
            "template": (
                "AbuseIPDB enrichment executed for extracted destination IP(s) "
                "(fan-out supported when an IP list is provided)."
            )
        },
        # STEP 5 — RCA
        {
            "name": "execute_python_from_s3",
            "parameters": {
                "s3_path": "s3://automation/stream-root-cause-analysis/threat_detections_and_preventions/rca.py",
                "function_name": "run_rca",
                "variables": {
                "sessions": "step.1.output",
                "event": "event",
                "vt_url": "step.3.output",
                "abuseipdb": "step.4.output"
            },
            },
            "template": (
            "Threat Detections/Preventions RCA completed: "
            "{{ output.verdict if output else 'n/a' }} "
            "(score {{ output.score if output else 'n/a' }}). "
            "Analysis included detection signals, policy behavior, URL reputation, "
            "and AbuseIPDB destination IP reputation."
        ),
        },

        # STEP 6 — EVALUATE
        {
            "name": "evaluate",
            "parameters": {
                "step": 5,
                "condition": "output.verdict == 'TRUE_POSITIVE' or output.verdict == 'SUSPICIOUS'",
                "if_step": 7,
                "else_step": 9
            },
            "template": "Evaluated the RCA verdict to decide whether to create an incident."
        },

        # STEP 7 — BUILD INCIDENT
        {
            "name": "execute_python",
            "parameters": {
                "code": "def _row_count(x):\n    if isinstance(x, dict):\n        r = x.get('result')\n        if isinstance(r, list):\n            return len(r)\n        rows = x.get('rows')\n        if isinstance(rows, list):\n            return len(rows)\n        return 0\n    if isinstance(x, list):\n        return len(x)\n    return 0\n\nrca_out = rca if isinstance(rca, dict) else {}\nverdict = rca_out.get('verdict') or 'n/a'\nscore = rca_out.get('score')\nscore_text = str(score) if score is not None else 'n/a'\nrows = _row_count(sessions)\nreason = rca_out.get('reason', '')\n\noutput = {\n  'title': f\"FortiGate Threat RCA: {verdict} (score {score_text})\",\n  'description': (\n    f\"Analyzed {rows} threat session event(s). \"\n    f\"Verdict: {verdict}, Score: {score_text}. \"\n    f\"Findings: {reason}\"\n  )\n}\n",
                "variables": {
                    "sessions": "step.1.output",
                    "rca": "step.5.output",
                    "event": "event"
                }
            },
            "template": "Incident payload prepared. Title: {{ output.title }}"
        },

        # STEP 8 — CREATE INCIDENT
        {
            "name": "action",
            "parameters": {
                "action": "CreateIncident",
                "fields": {
                    "incident": {
                        "step": 7,
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
        # STEP 9 — Execute Python
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
                    "incident_create": "step.8.output",
                    "rca": "step.5.output",
                },
            },
            "template": (
                "Status verdict for UpdateStatus: {{ output.verdict }} "
                "(FALSE_POSITIVE when incident create was a duplicate)."
            ),
        },
        # STEP 10 — UPDATE STATUS
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
                        "step": 9,
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
    RCA report for the detection UI — Fortigate Threat Detections And Preventions stream (HTML).

    Report bindings:
      - ``step_0`` — FortiGate threat/session telemetry.
      - ``step_1`` — extracted artifacts.
      - ``step_2`` — VirusTotal / enrichment output.
      - ``step_3`` — RCA verdict output.
      - ``event`` — detection payload from playbook execution document.
    """
    return """<div class="rca-report" style="font-family:system-ui,Segoe UI,sans-serif;line-height:1.45;white-space:normal;">

{%- set s1 = step_0|default({}, true) -%}
{%- set artifacts = step_1 if step_1 is defined and step_1 is mapping else {} -%}
{%- set vt_data = step_2 if step_2 is defined and step_2 is mapping else {} -%}
{%- set abuseip_data = step_3 if step_3 is defined and step_3 is mapping else {} -%}
{%- set rca = step_4|default({}, true) -%}

{%- set v = rca.get('verdict') if rca is mapping else none -%}
{%- set score = rca.get('score') if rca is mapping else none -%}
{%- set reason_text = rca.get('reason', '') if rca is mapping else '' -%}
{%- set conclusion_text = rca.get('conclusion', '') if rca is mapping else '' -%}

{%- set rows = (s1.get('result') if s1 is mapping else (s1 if s1 is iterable and s1 is not string else none)) -%}
{%- set src_ips = artifacts.get('unique_source_ips') or [] -%}
{%- set dst_ips = artifacts.get('unique_destination_ips') or [] -%}
{%- set urls = artifacts.get('urls') or artifacts.get('unique_urls') or [] -%}
{%- set actions = artifacts.get('unique_event_actions') or [] -%}
{%- set categories = artifacts.get('unique_categories') or [] -%}
{%- set threats = artifacts.get('threats') or [] -%}
{%- set signals = reason_text.split(' | ') if reason_text and reason_text.strip() else [] -%}

{%- set vt_hits = [] -%}
{%- set vt_responses = vt_data.get('responses', {}) if vt_data is mapping else {} -%}
{%- if vt_responses is mapping -%}
  {%- for url, data in vt_responses.items() -%}
    {%- set summary = data.get('summary', {}) if data is mapping else {} -%}
    {%- set nested = data.get('response', {}).get('data', {}).get('attributes', {}).get('last_analysis_stats', {}) if data is mapping else {} -%}
    {%- set stats = summary if summary else nested -%}
    {%- set malicious = stats.get('malicious', 0)|int if stats is mapping else 0 -%}
    {%- set suspicious = stats.get('suspicious', 0)|int if stats is mapping else 0 -%}
    {%- if malicious > 0 or suspicious > 0 -%}
      {%- set _ = vt_hits.append({'url': url, 'malicious': malicious, 'suspicious': suspicious}) -%}
    {%- endif -%}
  {%- endfor -%}
{%- endif -%}

{%- set abuseip_hits = [] -%}
{%- set abuseip_responses = abuseip_data.get('responses', {}) if abuseip_data is mapping else {} -%}
{%- if abuseip_responses is mapping -%}
  {%- for ip, result in abuseip_responses.items() -%}
    {%- set response = result.get('response', {}) if result is mapping else {} -%}
    {%- set data = response.get('data', {}) if response is mapping else {} -%}
    {%- set data = data if data else (result.get('data', result) if result is mapping else {}) -%}
    {%- set confidence = data.get('abuseConfidenceScore', 0)|int if data is mapping else 0 -%}
    {%- set reports = data.get('totalReports', 0)|int if data is mapping else 0 -%}
    {%- set countryName = data.get('countryName') if data is mapping else none -%}
    {%- set countryCode = data.get('countryCode') if data is mapping else none -%}
    {%- if confidence > 0 -%}
      {%- set _ = abuseip_hits.append({'ip': ip, 'confidence': confidence, 'reports': reports, 'countryName': countryName, 'countryCode': countryCode}) -%}
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
    <strong class="text-danger">High-risk FortiGate activity</strong>
    <p>Strong threat evidence matched the configured RCA rules.</p>
    {%- elif v == 'SUSPICIOUS' -%}
    <strong class="text-warning">Suspicious FortiGate activity</strong>
    <p>Risk evidence was found and requires follow-up validation.</p>
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
      <p>Retrieved FortiGate threat detection and prevention telemetry for the alert window.</p>
      <span class="label">Outcome:</span>
      {%- if rows is not none and rows is iterable and rows is not string -%}
      <p>{{ rows|length }} telemetry row(s) were reviewed. {{ threats|length }} event(s) matched RCA-relevant criteria.</p>
      {%- elif rows is not none -%}
      <p>Session output was present, but returned in a non-list shape.</p>
      {%- else -%}
      <p>No session output was available for this run.</p>
      {%- endif -%}
    </div>
  </section>

  <section class="card rca-block">
    <h2>Network Findings</h2>
    <div class="body-copy">
      <span class="label">Performed:</span>
      <p>Checked URL reputation, AbuseIPDB destination IP reputation, URL/category risk, firewall actions, threat-prevention logs, and anomaly indicators.</p>

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
          <div class="evidence-key">Flagged URLs</div>
          <div class="evidence-value">{{ vt_hits|length }} URL(s) with reputation concerns</div>
        </div>
        <div class="evidence-row">
          <div class="evidence-key">Flagged IPs</div>
          <div class="evidence-value">{{ abuseip_hits|length }} destination IP(s) with reputation concerns</div>
        </div>
      </div>

            {%- if abuseip_hits|length > 0 -%}
      <span class="label">Flagged IP Details:</span>
      <div class="evidence-list">
        {%- for hit in abuseip_hits[:3] -%}
        <div class="evidence-row">
          <div class="evidence-key">AbuseIPDB</div>
          <div class="evidence-value">
            <strong>{{ hit.ip }}</strong>{% if hit.countryName or hit.countryCode %} - {{ hit.countryName or '' }}{% if hit.countryCode %} ({{ hit.countryCode }}){% endif %}{% endif %}<br>
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
      <div class="evidence-list">
        <div class="evidence-row"><div class="evidence-key">Threat events</div><div class="evidence-value">{{ threats|length }} event(s) analyzed</div></div>

        {%- if urls|length > 0 -%}
        <div class="evidence-row"><div class="evidence-key">URLs</div><div class="evidence-value">{{ urls[:3]|join(', ')|e }}{% if urls|length > 3 %} <span title="{{ urls|join(', ')|e }}">(+{{ urls|length - 3 }} more)</span>{% endif %}</div></div>
        {%- endif -%}

        {%- if src_ips|length > 0 -%}
        <div class="evidence-row"><div class="evidence-key">Source IPs</div><div class="evidence-value">{{ src_ips[:3]|join(', ')|e }}{% if src_ips|length > 3 %} <span title="{{ src_ips|join(', ')|e }}">(+{{ src_ips|length - 3 }} more)</span>{% endif %}</div></div>
        {%- endif -%}

        {%- if dst_ips|length > 0 -%}
        <div class="evidence-row"><div class="evidence-key">Destination IPs</div><div class="evidence-value">{{ dst_ips[:3]|join(', ')|e }}{% if dst_ips|length > 3 %} <span title="{{ dst_ips|join(', ')|e }}">(+{{ dst_ips|length - 3 }} more)</span>{% endif %}</div></div>
        {%- endif -%}

        {%- if categories|length > 0 -%}
        <div class="evidence-row"><div class="evidence-key">Categories</div><div class="evidence-value">{{ categories[:3]|join(', ')|e }}</div></div>
        {%- endif -%}

        {%- if actions|length > 0 -%}
        <div class="evidence-row"><div class="evidence-key">Actions</div><div class="evidence-value">{{ actions[:3]|join(', ')|e }}</div></div>
        {%- endif -%}
      </div>
    </div>
  </section>

  <section class="assessment-panel">
    <h2 class="assessment-title">Final Assessment</h2>
    {%- if is_incident_dup -%}
    <p class="assessment-copy" style="border-left:3px solid #eab308;padding-left:0.75rem;margin-bottom:0.75rem;">
      RCA indicated <strong>{{ v or 'n/a' }}</strong>, but <strong>no new incident</strong> was created - an existing open incident was already available for same entity, entitytype and artifacts (<strong>{{ incident_dup_id }}</strong>).
    </p>
    {%- elif v == 'TRUE_POSITIVE' -%}
    <p class="assessment-copy"><strong>Assessment:</strong> High-risk malicious outbound communication or policy-permitted threat activity was identified{% if score is not none %}. <strong>Score {{ score }}.</strong>{% endif %}</p>
    {%- elif v == 'SUSPICIOUS' -%}
    <p class="assessment-copy"><strong>Assessment:</strong> Suspicious outbound behavior or risky destination activity was observed{% if score is not none %}. <strong>Score {{ score }}.</strong>{% endif %}</p>
    {%- elif v == 'FALSE_POSITIVE' -%}
    <p class="assessment-copy"><strong>Assessment:</strong> No meaningful threat evidence met the configured RCA threshold{% if score is not none %}. <strong>Score {{ score }}.</strong>{% endif %}</p>
    {%- else -%}
    <p class="assessment-copy"><strong>Assessment:</strong> Verdict is <strong>{{ v or 'pending or unavailable' }}</strong>.</p>
    {%- endif -%}
  </section>
</div>

<div class="rca-conclusion" data-rca-field="conclusion" style="display:none;">{{ conclusion_text }}</div>
</div>"""

# def template():
#     """
#     RCA report for the detection UI — Fortigate Threat Detections And Preventions stream (HTML).

#     Report bindings:
#       - ``step_0`` — FortiGate threat/session telemetry.
#       - ``step_1`` — extracted artifacts.
#       - ``step_2`` — VirusTotal / enrichment output.
#       - ``step_3`` — RCA verdict output.
#       - ``event`` — detection payload from playbook execution document.
#     """
#     return """<div class="rca-report" style="font-family:system-ui,Segoe UI,sans-serif;line-height:1.45;white-space:normal;">

# {%- set s1 = step_0|default({}, true) -%}
# {%- set artifacts = step_1 if step_1 is defined and step_1 is mapping else {} -%}
# {%- set vt_data = step_2 if step_2 is defined and step_2 is mapping else {} -%}
# {%- set abuseip_data = step_3 if step_3 is defined and step_3 is mapping else {} -%}
# {%- set rca = step_4|default({}, true) -%}

# {%- set v = rca.get('verdict') if rca is mapping else none -%}
# {%- set score = rca.get('score') if rca is mapping else none -%}
# {%- set reason_text = rca.get('reason', '') if rca is mapping else '' -%}
# {%- set conclusion_text = rca.get('conclusion', '') if rca is mapping else '' -%}

# {%- set rows = (s1.get('result') if s1 is mapping else (s1 if s1 is iterable and s1 is not string else none)) -%}
# {%- set src_ips = artifacts.get('unique_source_ips') or [] -%}
# {%- set dst_ips = artifacts.get('unique_destination_ips') or [] -%}
# {%- set urls = artifacts.get('urls') or artifacts.get('unique_urls') or [] -%}
# {%- set actions = artifacts.get('unique_event_actions') or [] -%}
# {%- set categories = artifacts.get('unique_categories') or [] -%}
# {%- set threats = artifacts.get('threats') or [] -%}
# {%- set signals = reason_text.split(' | ') if reason_text and reason_text.strip() else [] -%}

# {%- set vt_hits = [] -%}
# {%- set vt_responses = vt_data.get('responses', {}) if vt_data is mapping else {} -%}
# {%- if vt_responses is mapping -%}
#   {%- for url, data in vt_responses.items() -%}
#     {%- set summary = data.get('summary', {}) if data is mapping else {} -%}
#     {%- set nested = data.get('response', {}).get('data', {}).get('attributes', {}).get('last_analysis_stats', {}) if data is mapping else {} -%}
#     {%- set stats = summary if summary else nested -%}
#     {%- set malicious = stats.get('malicious', 0)|int if stats is mapping else 0 -%}
#     {%- set suspicious = stats.get('suspicious', 0)|int if stats is mapping else 0 -%}
#     {%- if malicious > 0 or suspicious > 0 -%}
#       {%- set _ = vt_hits.append({'url': url, 'malicious': malicious, 'suspicious': suspicious}) -%}
#     {%- endif -%}
#   {%- endfor -%}
# {%- endif -%}

# {%- set abuseip_hits = [] -%}
# {%- set abuseip_responses = abuseip_data.get('responses', {}) if abuseip_data is mapping else {} -%}
# {%- if abuseip_responses is mapping -%}
#   {%- for ip, result in abuseip_responses.items() -%}
#     {%- set response = result.get('response', {}) if result is mapping else {} -%}
#     {%- set data = response.get('data', {}) if response is mapping else {} -%}
#     {%- set data = data if data else (result.get('data', result) if result is mapping else {}) -%}
#     {%- set confidence = data.get('abuseConfidenceScore', 0)|int if data is mapping else 0 -%}
#     {%- set reports = data.get('totalReports', 0)|int if data is mapping else 0 -%}
#     {%- if confidence > 0 -%}
#       {%- set _ = abuseip_hits.append({'ip': ip, 'confidence': confidence, 'reports': reports}) -%}
#     {%- endif -%}
#   {%- endfor -%}
# {%- endif -%}

# {%- set inc_create = step_7|default({}, true) -%}
# {%- set incident_dup_id = inc_create.get('incident_id') if inc_create is mapping else none -%}
# {%- set resp = inc_create.get('responses') if inc_create is mapping else none -%}
# {%- set inner_dup = resp.get(incident_dup_id) if resp is mapping and incident_dup_id else none -%}
# {%- set is_incident_dup = (inc_create.get('duplicate') if inc_create is mapping else false) or (inner_dup is mapping and inner_dup.get('data') is mapping and inner_dup.get('data').get('duplicate')) -%}

# <div class="rca-body">
#   <section class="summary-strip">
#     {%- if v == 'TRUE_POSITIVE' -%}
#     <strong class="text-danger">High-risk FortiGate activity</strong>
#     <p>Strong threat evidence matched the configured RCA rules.</p>
#     {%- elif v == 'SUSPICIOUS' -%}
#     <strong class="text-warning">Suspicious FortiGate activity</strong>
#     <p>Risk evidence was found and requires follow-up validation.</p>
#     {%- elif v == 'FALSE_POSITIVE' -%}
#     <strong>Likely benign / false positive</strong>
#     <p>The reviewed telemetry and enrichment did not meet the configured risk threshold.</p>
#     {%- else -%}
#     <strong>RCA pending / unavailable</strong>
#     <p>The RCA output is incomplete or unavailable.</p>
#     {%- endif -%}
#   </section>

#   <section class="card rca-block">
#     <h2>Session Review</h2>
#     <div class="body-copy">
#       <p>Retrieved FortiGate threat detection and prevention telemetry for the alert window.</p>
#       <span class="label">Outcome:</span>
#       {%- if rows is not none and rows is iterable and rows is not string -%}
#       <p>{{ rows|length }} telemetry row(s) were reviewed. {{ threats|length }} event(s) matched RCA-relevant criteria.</p>
#       {%- elif rows is not none -%}
#       <p>Session output was present, but returned in a non-list shape.</p>
#       {%- else -%}
#       <p>No session output was available for this run.</p>
#       {%- endif -%}
#     </div>
#   </section>

#   <section class="card rca-block">
#     <h2>Network Findings</h2>
#     <div class="body-copy">
#       <span class="label">Performed:</span>
#       <p>Checked URL reputation, AbuseIPDB destination IP reputation, URL/category risk, firewall actions, threat-prevention logs, and anomaly indicators.</p>

#       <span class="label">Outcome:</span>
#       {%- if v -%}
#       <p>Verdict: <strong>{{ v }}</strong>{% if score is not none %} - aggregate score <strong>{{ score }}</strong>{% endif %}.</p>
#       {%- else -%}
#       <p><em>RCA output was not available.</em></p>
#       {%- endif -%}

#       <span class="label">Observed Signals:</span>
#       {%- if signals|length > 0 -%}
#       <p>
#         {%- for signal in signals -%}
#         - {{ signal|e }}{% if not loop.last %}<br>{% endif %}
#         {%- endfor -%}
#       </p>
#       {%- else -%}
#       <p>- No strong malicious behaviors were identified from available telemetry.</p>
#       {%- endif -%}

#       <span class="label">Reputation Summary:</span>
#       <div class="evidence-list">
#         <div class="evidence-row">
#           <div class="evidence-key">Flagged URLs</div>
#           <div class="evidence-value">{{ vt_hits|length }} URL(s) with reputation concerns</div>
#         </div>
#         <div class="evidence-row">
#           <div class="evidence-key">Flagged IPs</div>
#           <div class="evidence-value">{{ abuseip_hits|length }} destination IP(s) with reputation concerns</div>
#         </div>
#       </div>

#       {%- if abuseip_hits|length > 0 -%}
#       <span class="label">Flagged IP Details:</span>
#       <div class="evidence-list">
#         {%- for hit in abuseip_hits[:3] -%}
#         <div class="evidence-row">
#           <div class="evidence-key">AbuseIPDB</div>
#           <div class="evidence-value">
#             <strong>{{ hit.ip }}</strong><br>
#             {% if hit.confidence >= 80 %}malicious{% else %}suspicious{% endif %}
#             reputation - confidence {{ hit.confidence }}, {{ hit.reports }} report(s)
#           </div>
#         </div>
#         {%- endfor -%}
#       </div>
#       {%- endif -%}
#     </div>
#   </section>

#   <section class="card rca-block">
#     <h2>Artifacts Used</h2>
#     <div class="body-copy">
#       <div class="evidence-list">
#         <div class="evidence-row"><div class="evidence-key">Threat events</div><div class="evidence-value">{{ threats|length }} event(s) analyzed</div></div>

#         {%- if urls|length > 0 -%}
#         <div class="evidence-row"><div class="evidence-key">URLs</div><div class="evidence-value">{{ urls[:3]|join(', ')|e }}{% if urls|length > 3 %} <span title="{{ urls|join(', ')|e }}">(+{{ urls|length - 3 }} more)</span>{% endif %}</div></div>
#         {%- endif -%}

#         {%- if src_ips|length > 0 -%}
#         <div class="evidence-row"><div class="evidence-key">Source IPs</div><div class="evidence-value">{{ src_ips[:3]|join(', ')|e }}{% if src_ips|length > 3 %} <span title="{{ src_ips|join(', ')|e }}">(+{{ src_ips|length - 3 }} more)</span>{% endif %}</div></div>
#         {%- endif -%}

#         {%- if dst_ips|length > 0 -%}
#         <div class="evidence-row"><div class="evidence-key">Destination IPs</div><div class="evidence-value">{{ dst_ips[:3]|join(', ')|e }}{% if dst_ips|length > 3 %} <span title="{{ dst_ips|join(', ')|e }}">(+{{ dst_ips|length - 3 }} more)</span>{% endif %}</div></div>
#         {%- endif -%}

#         {%- if categories|length > 0 -%}
#         <div class="evidence-row"><div class="evidence-key">Categories</div><div class="evidence-value">{{ categories[:3]|join(', ')|e }}</div></div>
#         {%- endif -%}

#         {%- if actions|length > 0 -%}
#         <div class="evidence-row"><div class="evidence-key">Actions</div><div class="evidence-value">{{ actions[:3]|join(', ')|e }}</div></div>
#         {%- endif -%}
#       </div>
#     </div>
#   </section>

#   <section class="assessment-panel">
#     <h2 class="assessment-title">Final Assessment</h2>
#     {%- if is_incident_dup -%}
#     <p class="assessment-copy" style="border-left:3px solid #eab308;padding-left:0.75rem;margin-bottom:0.75rem;">
#       RCA indicated <strong>{{ v or 'n/a' }}</strong>, but <strong>no new incident</strong> was created - an existing open incident was already available for same entity, entitytype and artifacts (<strong>{{ incident_dup_id }}</strong>).
#     </p>
#     {%- elif v == 'TRUE_POSITIVE' -%}
#     <p class="assessment-copy"><strong>Assessment:</strong> High-risk malicious outbound communication or policy-permitted threat activity was identified{% if score is not none %}. <strong>Score {{ score }}.</strong>{% endif %}</p>
#     {%- elif v == 'SUSPICIOUS' -%}
#     <p class="assessment-copy"><strong>Assessment:</strong> Suspicious outbound behavior or risky destination activity was observed{% if score is not none %}. <strong>Score {{ score }}.</strong>{% endif %}</p>
#     {%- elif v == 'FALSE_POSITIVE' -%}
#     <p class="assessment-copy"><strong>Assessment:</strong> No meaningful threat evidence met the configured RCA threshold{% if score is not none %}. <strong>Score {{ score }}.</strong>{% endif %}</p>
#     {%- else -%}
#     <p class="assessment-copy"><strong>Assessment:</strong> Verdict is <strong>{{ v or 'pending or unavailable' }}</strong>.</p>
#     {%- endif -%}
#   </section>
# </div>

# <div class="rca-conclusion" data-rca-field="conclusion" style="display:none;">{{ conclusion_text }}</div>
# </div>"""