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
                        "path": "event",
                    }
                },
            },
            "template": (
                "EventSession: retrieved "
                "{{ (output.result|length if output is mapping and output.result is iterable and output.result is not string else (output.rows|length if output is mapping and output.rows is iterable and output.rows is not string else (output|length if output is iterable and output is not string else 'n/a'))) }} "
                "Windows network session row(s) for RCA. "
                "Gathered SMB/DNS-related network evidence for lateral movement and name resolution anomaly checks."
            )
        },#step 1
        {
            "name": "threatlab",
            "parameters": {
                "threat_intel_id": "threatintel.virustotal.file_reputation",
                "input": {
                    # Tune this path to the domain field in your execution event.
                    "hash": "event.file_hash"
                },
            },
            "template": "VirusTotal file hash reputation enrichment executed"
        },#step 2
        {
            "name": "threatlab",
            "parameters": {
                "threat_intel_id": "threatintel.virustotal.domain_reputation",
                "input": {
                    # Tune this path to the domain field in your execution event.
                    "domain": "event.source_account_domain"
                },
            },
            "template": "VirusTotal domain reputation enrichment executed for source account domain(s) "
                "(fan-out supported when a domain list is provided)."
        },#step 3
        {
            "name": "execute_python_from_s3",
            "parameters": {
                "s3_path": "s3://automation/stream-root-cause-analysis/windows_network_smb_dns_activity_monitoring/rca.py",
                "function_name": "run_rca",
                "variables": {
                      "sessions": "step.1.output",
                    "file_threatlab_report": "step.2.output",
                    "domain_threatlab_report": "step.3.output"
                },
            },
            "template": (
                "Windows SMB/DNS Network RCA completed: "
                "{{ output.verdict if output else 'n/a' }} "
                "(score {{ output.score if output else 'n/a' }}). "
                "Heuristics executed: SMB/DNS activity anomaly evaluation for lateral movement and suspicious name resolution patterns."
            ),
        },#step 4
        {
            "name": "evaluate",
            "parameters": {
                "step": 4,
                "condition": "output.verdict == 'TRUE_POSITIVE'",
                "if_step": 6,
                "else_step": 8
            },
            "template": "Evaluated the RCA verdict to decide whether to create an incident."
        },#step 5
        {
            "name": "execute_python",
            "parameters": {
                "code": "def _row_count(x):\n    if isinstance(x, dict):\n        r = x.get('result')\n        if isinstance(r, list):\n            return len(r)\n        rows = x.get('rows')\n        if isinstance(rows, list):\n            return len(rows)\n        return 0\n    if isinstance(x, list):\n        return len(x)\n    return 0\n\nrca_out = rca if isinstance(rca, dict) else {}\nverdict = rca_out.get('verdict') or 'n/a'\nscore = rca_out.get('score')\nscore_text = str(score) if score is not None else 'n/a'\nrows = _row_count(sessions)\n\noutput = {\n  'title': f\"Windows SMB/DNS Activity RCA: {verdict} (score {score_text})\",\n  'description': (\n    f\"Analyzed {rows} Windows network session row(s) for SMB/DNS anomalies indicative of lateral movement or suspicious name resolution behavior. \"\n    f\"Result: {verdict} with aggregate score {score_text}.\"\n  )\n}\n",
                "variables": {
                    "sessions": "step.1.output",
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
            "template": 
              "{% set inner = output.responses[output.incident_id] "
              "   if output and output.responses and output.incident_id "
              "   and output.incident_id in output.responses "
              "   else (output.responses.values()|list|first "
              "         if output and output.responses else none) %}"
              "{{ inner.result if inner and inner.result is defined else output.incident_id }}"
        },#step 7
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
                    "incident_create": "step.6.output",
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
        }#step 9
    ]


def template():
    """
    RCA report for the detection UI — Palo Alto Web / DNS Intelligence stream (HTML).

    Report bindings:
      - step_0: EventSession output
      - step_1: ThreatLab output (VirusTotal File Reputation)
      - step_2: ThreatLab output (VirusTotal Domain Reputation)
      - step_3: run_rca output (verdict/score/reason)
      - event: execution/detection payload
    """
    return """<div class="rca-report" style="font-family:system-ui,Segoe UI,sans-serif;line-height:1.45;white-space:normal;">

{%- set s1 = step_0|default({}, true) -%}
{%- set s2 = step_1|default({}, true) -%}
{%- set s3 = step_1|default({}, true) -%}
{%- set rca = step_3|default({}, true) -%}
{%- set ev = event|default({}, true) -%}
{%- set v = rca.get('verdict') -%}
{%- set score = rca.get('score') -%}
{%- set reason_text = rca.get('reason', '') -%}
{%- set conclusion_text = rca.get('conclusion', '') -%}
{%- set rows = (s1.get('result') if s1 is mapping else (s1 if s1 is iterable and s1 is not string else none)) -%}
{%- set _r0 = rows[0] if rows is not none and rows is iterable and rows is not string and rows|length > 0 else none -%}
{%- set domain = (ev.get('domain') or ev.get('destination_domain') or ev.get('fqdn')) if ev is mapping else none -%}
{%- set domain = domain or ((_r0.get('domain') or _r0.get('destination_domain') or _r0.get('fqdn')) if _r0 is mapping else none) -%}

{%- set inc_create = step_6|default({}, true) -%}
{%- set incident_dup_id = inc_create.get('incident_id') if inc_create is mapping else none -%}
{%- set resp = inc_create.get('responses') if inc_create is mapping else none -%}
{%- set inner_dup = resp.get(incident_dup_id) if resp is mapping and incident_dup_id else none -%}
{%- set is_incident_dup = (inc_create.get('duplicate') if inc_create is mapping else false) or (inner_dup is mapping and inner_dup.get('data') is mapping and inner_dup.get('data').get('duplicate')) -%}

<section style="margin:0 0 .85rem 0;">
<h3 style="font-size:.92rem;margin:.5rem 0 .25rem 0;">Step 1 - Session data</h3>
<p style="margin:0 0 .25rem 0;">Performed query to retrieve web/DNS session rows for beaconing analysis.</p>
<p style="margin:0 0 .15rem 0;"><strong>Outcome:</strong></p>
<ul style="margin:0 0 0 1rem;padding:0;">
{%- if rows is not none and rows is iterable and rows is not string -%}
<li><strong>Rows returned:</strong> {{ rows|length }} flow row(s){% if src_ip %} (sample source <strong>{{ src_ip }}</strong>){% endif %}.</li>
{%- elif rows is not none -%}
<li><strong>Result:</strong> present (non-list shape).</li>
{%- else -%}
<li>No session output in this run.</li>
{%- endif -%}
</ul>

<h3 style="font-size:.92rem;margin:.5rem 0 .25rem 0;">Step 2 - Threat intelligence (VirusTotal)</h3>
<p style="margin:0 0 .25rem 0;"><strong>Performed:</strong> Domain reputation lookup{% if domain %} for <strong>{{ domain }}</strong>{% else %} <em style="color:#666;">(domain not resolved)</em>{% endif %}.</p>
<p style="margin:0 0 .15rem 0;"><strong>Outcome:</strong></p>
<ul style="margin:0 0 0 1rem;padding:0;">
{%- if s2 is mapping -%}
<li>
{%- if s2.get('message') -%}{{ s2.get('message') }}{%- endif -%}
{%- set summ = s2.get('summary') if s2.get('summary') is mapping else {} -%}
{%- if summ and (summ.get('malicious') is not none or summ.get('suspicious') is not none) -%}
 — malicious {{ summ.get('malicious', 0) }}, suspicious {{ summ.get('suspicious', 0) }}, harmless {{ summ.get('harmless', 0) }}, undetected {{ summ.get('undetected', 0) }}
{%- elif summ and summ.get('positives') is not none -%}
 — positives {{ summ.get('positives') }} / {{ summ.get('total') }}
{%- endif -%}
</li>
{%- else -%}
<li><em>ThreatLab file reputation output not available.</em></li>
{%- endif -%}
</ul>
<ul style="margin:0 0 0 1rem;padding:0;">
{%- if s3 is mapping -%}
<li>
{%- if s3.get('message') -%}{{ s3.get('message') }}{%- endif -%}
{%- set summ = s3.get('summary') if s3.get('summary') is mapping else {} -%}
{%- if summ and (summ.get('malicious') is not none or summ.get('suspicious') is not none) -%}
 — malicious {{ summ.get('malicious', 0) }}, suspicious {{ summ.get('suspicious', 0) }}, harmless {{ summ.get('harmless', 0) }}, undetected {{ summ.get('undetected', 0) }}
{%- elif summ and summ.get('positives') is not none -%}
 — positives {{ summ.get('positives') }} / {{ summ.get('total') }}
{%- endif -%}
</li>
{%- else -%}
<li><em>ThreatLab domain reputation output not available.</em></li>
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
<p style="margin:0;"><strong>Assessment:</strong> This detection is classified as <strong>confirmed malicious beaconing</strong> based on interval consistency and domain reputation context{% if score is not none %}. The aggregated risk score is <strong>{{ score }}</strong>{% else %}; no aggregate risk score was computed{% endif %}.</p>
{%- elif v == 'SUSPICIOUS' -%}
<p style="margin:0;"><strong>Assessment:</strong> Findings are <strong>suspicious</strong> — validate domain ownership, expected automated traffic, and correlate with adjacent alerts{% if score is not none %}. Aggregated risk score <strong>{{ score }}</strong>{% else %}; no aggregate risk score was computed{% endif %}.</p>
{%- elif v == 'FALSE_POSITIVE' -%}
<p style="margin:0;"><strong>Assessment:</strong> Treated as <strong>false positive / low signal</strong> for this rule set — beaconing consistency and TI context did not indicate malicious activity{% if score is not none %}. Aggregated risk score <strong>{{ score }}</strong>{% else %}; no aggregate risk score was computed{% endif %}.</p>
{%- else -%}
<p style="margin:0;"><strong>Assessment:</strong> Verdict is <strong>{{ v or 'pending or unavailable' }}</strong>{% if score is not none %} with aggregate RCA risk score <strong>{{ score }}</strong>{% else %}; risk score was not computed{% endif %}.</p>
{%- endif -%}
</section>

{%- if reason_text and reason_text.strip() -%}
<hr style="border:0;border-top:1px solid #e0e0e0;margin:.65rem 0;" />
<section style="margin:0;">
<h2 style="font-size:1.02rem;margin:0 0 .35rem 0;border-bottom:1px solid #ddd;padding-bottom:.2rem;">Findings</h2>
<ul style="margin:0 0 0 1rem;padding:0;">
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

