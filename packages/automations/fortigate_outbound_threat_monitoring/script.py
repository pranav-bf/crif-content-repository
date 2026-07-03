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
                        "path": "event"
                    }
                }
            },
            "template": "EventSession: retrieved "
                "{{ (output.result|length if output is mapping and output.result is iterable and output.result is not string else (output.rows|length if output is mapping and output.rows is iterable and output.rows is not string else (output|length if output is iterable and output is not string else 'n/a'))) }} "
                "outbound traffic session row(s) for RCA. "
                "Gathered egress flow evidence for exfiltration/tunneling indicators and enrichment targets."
        }, # step 1 

        {
            "name": "execute_python_from_s3",
            "parameters": {
                "s3_path": "s3://automation/stream-root-cause-analysis/utils/extract_distinct_destination_ips.py",
                "function_name": "extract_distinct_destination_ips",
                "variables": {
                    "sessions": "step.1.output"
                }
            },
            "template": "Extracted distinct destination IP(s) for enrichment: "
                "{{ output|length if output is iterable and output is not string else 'n/a' }} unique IP(s)."
        },# step 2

        {
        "name": "action",
        "parameters": {
            "action": "LookupIpv4",
            "fields": {
                "ipaddress": {
                    "step": 2,
                    "path": "output"
                }
            }
        },
            "template": "Geo-location lookup completed for destination IP indicators."
        }, # step 3

        {
        "name": "action",
        "parameters": {
            "action": "BlacklistedCountries",
            "fields": {
                "country": {
                    "step": 3,
                    "path": "output.responses.*.rows[0][5]"
                }
            }
        },
            "template": "Blacklist country verification completed for resolved destinations."
        }, # step 4

        {
            "name": "execute_python_from_s3",
            "parameters": {
                "s3_path": "s3://automation/stream-root-cause-analysis/outbound_threat_monitoring/rca.py",
                "function_name": "run_rca",
                "variables": {
                    "sessions": "step.0.output",
                    "intel": "step.4.output",
                    "event": "event"
                }
            },
            "template": (
                "Outbound Threat Monitoring RCA completed: "
                "{{ output.verdict if output else 'n/a' }} "
                "(score {{ output.score if output else 'n/a' }}). "
                "Heuristics executed: outbound egress risk evaluation (geo/time/volume/tunneling indicators) "
                "plus AbuseIPDB IP reputation context when available."
            )
        }, # step 5
        {
            "name": "evaluate",
            "parameters": {
                "step": 5,
                "condition": "output != None and output.verdict == 'TRUE_POSITIVE'",
                "if_step": 8,
                "else_step": 9
            },
            "template": "Analyzed the verdict and initiated a decision on incident creation."
          },# step 6
        {
            "name": "execute_python",
            "parameters": {
                "code": "def _row_count(x):\n    if isinstance(x, dict):\n        r = x.get('result')\n        if isinstance(r, list):\n            return len(r)\n        rows = x.get('rows')\n        if isinstance(rows, list):\n            return len(rows)\n        return 0\n    if isinstance(x, list):\n        return len(x)\n    return 0\n\nrca_out = rca if isinstance(rca, dict) else {}\nverdict = rca_out.get('verdict') or 'n/a'\nscore = rca_out.get('score')\nscore_text = str(score) if score is not None else 'n/a'\nrows = _row_count(sessions)\n\noutput = {\n  'title': f\"FortiGate Outbound Threat Monitoring RCA: {verdict} (score {score_text})\",\n  'description': (\n    f\"Analyzed {rows} outbound traffic session row(s) for egress risk (geo/time anomalies, volume spikes, and tunneling indicators), with enrichment context where available. \"\n    f\"Result: {verdict} with aggregate score {score_text}.\"\n  )\n}\n",
                "variables": {
                }
            },
            "template": "Title: {{ output.title }}\nDescription: {{ output.description }}"
        },# step 7
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
        },# step 8
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
        },# step 9
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
        }# step 10
    ]



def template():
    """
    RCA report for the detection UI — Fortigate Outbound Threat Monitoring stream (HTML).

    Report bindings (see genai-playbook-executor ``report_generation.process_message_report``):
      - ``step_1`` … ``step_n`` — outputs from each playbook step.
      - ``event`` — detection payload from Mongo ``playbook`` execution document
        (``data_manager.get_execution_event(execution_id)``), same object passed into
        the run as ``event`` in steps. Use ``event.destination_ip`` if your payload
        includes it; otherwise the template falls back to session row fields.

    If ``event`` is empty in the report, confirm the executor build includes the
    report context merge and that executions store an ``event`` field.
    """
    return """<div class="rca-report" style="font-family:system-ui,Segoe UI,sans-serif;line-height:1.45;white-space:normal;">

{%- set s1 = step_0|default({}, true) -%}
{%- set extracted_ips = step_1|default([], true) -%}
{%- set s2 = step_2|default({}, true) -%}
{%- set s3 = step_3|default({}, true) -%}
{%- set rca = step_4|default({}, true) -%}
{%- set ev = event|default({}, true) -%}
{%- set v = rca.get('verdict') -%}
{%- set score = rca.get('score') -%}
{%- set reason_text = rca.get('reason', '') -%}
{%- set conclusion_text = rca.get('conclusion', '') -%}
{%- set rows = (s1.get('result') if s1 is mapping else (s1 if s1 is iterable and s1 is not string else none)) -%}
{%- set _r0 = rows[0] if rows is not none and rows is iterable and rows is not string and rows|length > 0 else none -%}

{%- set inc_create = step_7|default({}, true) -%}
{%- set incident_dup_id = inc_create.get('incident_id') if inc_create is mapping else none -%}
{%- set resp = inc_create.get('responses') if inc_create is mapping else none -%}
{%- set inner_dup = resp.get(incident_dup_id) if resp is mapping and incident_dup_id else none -%}
{%- set is_incident_dup = (inc_create.get('duplicate') if inc_create is mapping else false) or (inner_dup is mapping and inner_dup.get('data') is mapping and inner_dup.get('data').get('duplicate')) -%}

<section style="margin:0 0 .85rem 0;">
<h3 style="font-size:.92rem;margin:.5rem 0 .25rem 0;">Step 1 - Session data</h3>
<p style="margin:0 0 .25rem 0;">Performed query to retrieve session data.</p>
<p style="margin:0 0 .15rem 0;"><strong>Outcome:</strong></p>
<ul style="margin:0 0 0 1rem;padding:0;">
{%- if rows is not none and rows is iterable and rows is not string -%}
<li><strong>Rows returned:</strong> {{ rows|length }} session row(s).</li>
{%- elif rows is not none -%}
<li><strong>Result:</strong> present (non-list shape).</li>
{%- else -%}
<li>No session output in this run.</li>
{%- endif -%}
</ul>

<h3 style="font-size:.92rem;margin:.5rem 0 .25rem 0;">Step 2 - Distinct Destination IPs</h3>
<p style="margin:0 0 .25rem 0;">Computed distinct destination IPs from session rows for enrichment.</p>
<p style="margin:0 0 .15rem 0;"><strong>Outcome:</strong></p>
<ul style="margin:0 0 0 1rem;padding:0;">
{%- if extracted_ips is iterable and extracted_ips is not string -%}
<li><strong>Unique destination IPs:</strong> {{ extracted_ips|length }}{% if extracted_ips|length > 0 %} (sample <strong>{{ extracted_ips[0] }}</strong>){% endif %}</li>
{%- else -%}
<li>No extracted IPs in this run.</li>
{%- endif -%}
</ul>

<h3 style="font-size:.92rem;margin:.5rem 0 .25rem 0;">Step 3 - Geo Location Lookup</h3>
<p style="margin:0 0 .25rem 0;">Resolved country information for destination IP indicators.</p>
<p style="margin:0 0 .15rem 0;"><strong>Outcome:</strong></p>
<ul style="margin:0 0 0 1rem;padding:0;">
{%- if s2 is mapping and s2.get('responses') is mapping and s2.get('responses')|length > 0 -%}
{%- set ns = namespace(countries=[]) -%}
{%- for ip, resp in s2.get('responses').items() -%}
    {%- if resp.get('rows') and resp.get('rows')|length > 0 and resp.get('rows')[0]|length > 5 -%}
        {%- set cname = resp.get('rows')[0][5] -%}
        {%- if cname and cname not in ns.countries -%}
            {%- set ns.countries = ns.countries + [cname] -%}
        {%- endif -%}
    {%- endif -%}
{%- endfor -%}
<li>
{%- if ns.countries|length > 0 -%}
Country detected from destination IP(s): <strong>{{ ns.countries|join(', ') }}</strong>
{%- else -%}
Geo location resolved but no country values found.
{%- endif -%}
</li>
{%- else -%}
<li>No geo lookup output available.</li>
{%- endif -%}
</ul>

<h3 style="font-size:.92rem;margin:.5rem 0 .25rem 0;">Step 4 - Blacklisted Country Verification</h3>
<p style="margin:0 0 .25rem 0;">Checked resolved countries against blacklist intelligence.</p>
<p style="margin:0 0 .15rem 0;"><strong>Outcome:</strong></p>
<ul style="margin:0 0 0 1rem;padding:0;">
{%- if s3 is mapping and s3.get('responses') is mapping and s3.get('responses')|length > 0 -%}
{%- set ns2 = namespace(matches=[]) -%}
{%- for cname, resp in s3.get('responses').items() -%}
    {%- if resp.get('rows') and resp.get('rows')|length > 0 -%}
        {%- set ns2.matches = ns2.matches + [cname] -%}
    {%- endif -%}
{%- endfor -%}
<li>
{%- if ns2.matches|length > 0 -%}
<strong>{{ ns2.matches|join(', ') }}</strong> matches the blacklisted country list.
{%- else -%}
No blacklisted country found.
{%- endif -%}
</li>
{%- else -%}
<li>No blacklist output available.</li>
{%- endif -%}
</ul>

</section>

<hr style="border:0;border-top:1px solid #e0e0e0;margin:.65rem 0;" />

<section style="margin:0 0 .85rem 0;">
<h2 style="font-size:1.02rem;margin:0 0 .35rem 0;border-bottom:1px solid #ddd;padding-bottom:.2rem;">Verdict &amp; Risk assessment</h2>
{%- if is_incident_dup -%}
    <p class="assessment-copy" style="border-left:3px solid #eab308;padding-left:0.75rem;margin-bottom:0.75rem;">
      RCA indicated <strong>{{ v or 'n/a' }}</strong>, but <strong>no new incident</strong> was created — an existing open incident was reused (<strong>{{ incident_dup_id }}</strong>).
      Detection status was set to <strong>FALSE_POSITIVE</strong> for deduplication alignment.
    </p>
    {%- endif -%}
{%- if v == 'TRUE_POSITIVE' -%}
<p style="margin:0;"><strong>Assessment:</strong> This detection is classified as <strong>confirmed malicious or high-fidelity threat activity</strong>{% if score is not none %}. The aggregated risk score is <strong>{{ score }}</strong>{% else %}; no aggregate risk score was computed for this run{% endif %}.</p>
{%- elif v == 'SUSPICIOUS' -%}
<p style="margin:0;"><strong>Assessment:</strong> Findings are <span class='highlight-artifact mb-1 medium'>suspicious</span> - validate signatures and destinations, correlate with enrichment, asset ownership, and business context before closing{% if score is not none %}. Aggregated risk score <strong>{{ score }}</strong>{% else %}; no aggregate risk score was computed{% endif %}.</p>
{%- elif v == 'FALSE_POSITIVE' -%}
<p style="margin:0;"><strong>Assessment:</strong> Treated as <span class='highlight-artifact mb-1 low'>false positive / likely benign</span> for this rule set{% if score is not none %}. Aggregated risk score <strong>{{ score }}</strong>{% else %}; no aggregate risk score was computed{% endif %}.</p>
{%- else -%}
<p style="margin:0;"><strong>Assessment:</strong> Verdict is <strong>{{ v or 'pending or unavailable' }}</strong>{% if score is not none %} with aggregate RCA risk score <strong>{{ score }}</strong>{% else %}; risk score was not computed{% endif %}.</p>
{%- endif -%}
</section>

{%- if reason_text and reason_text.strip() -%}
<hr style="border:0;border-top:1px solid #e0e0e0;margin:.65rem 0;" />
<section style="margin:0;">
<h2 style="font-size:1.02rem;margin:0 0 .35rem 0;border-bottom:1px solid #ddd;padding-bottom:.2rem;">Findings</h2>
<ul style="margin:0;padding:0;">
{%- for clause in reason_text.split(' | ') -%}
{%- if clause.strip() -%}
<li>{{ clause.strip() }}</li>
{%- endif -%}
{%- endfor -%}
</ul>
</section>
{%- endif -%}
<div class="rca-conclusion" data-rca-field="conclusion" style="display:none;">{{ conclusion_text }}</div>
</div>"""


