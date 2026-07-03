
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
                "Linux identity/credential-related session row(s) for RCA. "
                "Gathered evidence for credential access attempts, account changes, and anomalous identity activity."
        },
        {
            "name": "execute_python_from_s3",
            "parameters": {
                "s3_path": "s3://automation/stream-root-cause-analysis/linux_identity_credential_access_monitoring/rca.py",
                "function_name": "run_rca",
                "variables": {
                    "sessions": "step.1.output"
                },
            },
            "template": (
                "Linux Identity/Credential Access RCA completed: "
                "{{ output.verdict if output else 'n/a' }} "
                "(score {{ output.score if output else 'n/a' }}). "
                "Heuristics executed: credential access and identity anomaly checks over sampled sessions."
            ),
        },
        {
            "name": "evaluate",
            "parameters": {
                "step": 2,
                "condition": "output.verdict == 'TRUE_POSITIVE'",
                "if_step": 4,
                "else_step": 6
            },
            "template": "Evaluated the RCA verdict to decide whether to create an incident."
        },
        {
            "name": "execute_python",
            "parameters": {
                "code": "def _row_count(x):\n    if isinstance(x, dict):\n        r = x.get('result')\n        if isinstance(r, list):\n            return len(r)\n        rows = x.get('rows')\n        if isinstance(rows, list):\n            return len(rows)\n        return 0\n    if isinstance(x, list):\n        return len(x)\n    return 0\n\nrca_out = rca if isinstance(rca, dict) else {}\nverdict = rca_out.get('verdict') or 'n/a'\nscore = rca_out.get('score')\nscore_text = str(score) if score is not None else 'n/a'\nrows = _row_count(sessions)\n\noutput = {\n  'title': f\"Linux Identity/Credential Access RCA: {verdict} (score {score_text})\",\n  'description': (\n    f\"Analyzed {rows} Linux session row(s) for identity and credential access anomalies. \"\n    f\"Result: {verdict} with aggregate score {score_text}.\"\n  )\n}",
                "variables": {
                    "sessions": "step.1.output",
                    "rca": "step.2.output",
                    "event": "event"
                }
            },
            "template": "Incident payload prepared. Title: {{ output.title }}"
        },
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
            "template": "Incident created successfully. ID: {{ output.incident_id if output else 'Unknown' }}."
        },
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
                        "step": 2,
                        "path": "output.verdict"
                    },
                    "detectiontime": {
                        "step": 0,
                        "path": "detectiontime",
                    },
                }
            },
            "template": "The alert status was modified in accordance with the verdict."
        }
    ]


def template():
    """
    RCA report for the detection UI — Palo Alto Network Traffic Intelligence stream (HTML).

    Report bindings (see ``report_generation.process_message_report``):
      - ``step_0``, ``step_1`` — outputs from each playbook step (0-based).
      - ``event`` — detection payload from playbook execution document.

    Same ``variables`` shape as threat-intelligence RCA (minus ``threatlab_execute``): ``sessions`` from
    EventSession, ``event`` from the execution payload.
    """
    return """<div class="rca-report" style="font-family:system-ui,Segoe UI,sans-serif;line-height:1.45;white-space:normal;">

{%- set s1 = step_0|default({}, true) -%}
{%- set rca = step_1|default({}, true) -%}
{%- set ev = event|default({}, true) -%}
{%- set v = rca.get('verdict') -%}
{%- set score = rca.get('score') -%}
{%- set reason_text = rca.get('reason', '') -%}
{%- set conclusion_text = rca.get('conclusion', '') -%}
{%- set rows = (s1.get('result') if s1 is mapping else (s1 if s1 is iterable and s1 is not string else none)) -%}
{%- set _r0 = rows[0] if rows is not none and rows is iterable and rows is not string and rows|length > 0 else none -%}
{%- set src_ip = (ev.get('source_ip') or ev.get('sourceip') or ev.get('src_ip') or ev.get('src')) if ev is mapping else none -%}
{%- set src_ip = src_ip or ((_r0.get('source_ip') or _r0.get('src_ip') or _r0.get('src') or _r0.get('sourceip')) if _r0 is mapping else none) -%}

<section style="margin:0 0 .85rem 0;">
<h3 style="font-size:.92rem;margin:.5rem 0 .25rem 0;">Step 1 - Session data</h3>
<p style="margin:0 0 .25rem 0;">Performed query to retrieve network traffic session rows for anomaly analysis.</p>
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
<h3 style="font-size:.92rem;margin:.5rem 0 .25rem 0;">Step 2 - Network traffic RCA</h3>
<p style="margin:0 0 .25rem 0;"><strong>Performed:</strong> Palo Alto NTI heuristics (SSL on non-standard ports, tunneling, deny volume, fan-out destinations, large outbound bytes).</p>
<p style="margin:0 0 .15rem 0;"><strong>Outcome:</strong></p>
<ul style="margin:0 0 0 1rem;padding:0;">
{%- if rca is mapping and rca.get('verdict') -%}
<li><strong>Verdict:</strong> {{ rca.get('verdict') }}{% if score is not none %} - aggregate score <strong>{{ score }}</strong>{% endif %}</li>
{%- else -%}
<li><em>RCA output not available.</em></li>
{%- endif -%}
</ul>
</section>
<hr style="border:0;border-top:1px solid #e0e0e0;margin:.65rem 0;" />
<section style="margin:0 0 .85rem 0;">
<h2 style="font-size:1.02rem;margin:0 0 .35rem 0;border-bottom:1px solid #ddd;padding-bottom:.2rem;">Verdict &amp; Risk assessment</h2>
{%- if v == 'TRUE_POSITIVE' -%}
<p style="margin:0;"><strong>Assessment:</strong> Session traffic patterns support <strong>confirmed or high-risk anomaly</strong> for this rule set (e.g. tunneling, large exfil-style volume, or strong deny/fan-out signals){% if score is not none %}. Aggregated risk score is <strong>{{ score }}</strong>{% else %}; no aggregate score recorded{% endif %}.</p>
{%- elif v == 'SUSPICIOUS' -%}
<p style="margin:0;"><strong>Assessment:</strong> Findings are <strong>suspicious</strong> — validate time range, asset role, and adjacent alerts before closing{% if score is not none %}. Score <strong>{{ score }}</strong>{% else %}; no aggregate score recorded{% endif %}.</p>
{%- elif v == 'FALSE_POSITIVE' -%}
<p style="margin:0;"><strong>Assessment:</strong> Treated as <strong>false positive / low signal</strong> for these heuristics - no strong aggregate anomaly from analyzed flows{% if score is not none %}. Score <strong>{{ score }}</strong>{% else %}; no aggregate score recorded{% endif %}.</p>
{%- else -%}
<p style="margin:0;"><strong>Assessment:</strong> Verdict is <strong>{{ v or 'pending or unavailable' }}</strong>{% if score is not none %} with score <strong>{{ score }}</strong>{% else %}; score not computed{% endif %}.</p>
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
