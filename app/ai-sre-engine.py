import os
import json
import hashlib
import time
import threading
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler

import requests
from kubernetes import client, config, watch

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://ollama.aiontime.svc.cluster.local:11434/api/generate")
MODEL = os.getenv("OLLAMA_MODEL", "llama3.1")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "5"))
WINDOW_SECONDS = int(os.getenv("WINDOW_SECONDS", "30"))
WEBHOOK_URL = os.getenv("WEBHOOK_URL")
METRICS_PORT = int(os.getenv("METRICS_PORT", "8080"))

incidents = []

class State:
    DETECTED = "DETECTED"
    ANALYZED = "ANALYZED"
    RESOLVED = "RESOLVED"

class Incident:
    def __init__(self, incident_id, key, events):
        self.id = incident_id
        self.key = key
        self.events = events
        self.state = State.DETECTED
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.report = None

    def advance(self, state):
        self.state = state

    def to_dict(self):
        return {"id": self.id, "state": self.state, "created_at": self.created_at, "report": self.report, "events": self.events[-5:]}

class IncidentTracker:
    def __init__(self):
        self.cache = {}
        self.counter = 0

    def _key(self, events):
        fingerprint = sorted({(e["reason"], e["name"], e["namespace"]) for e in events})
        window = int(time.time() / WINDOW_SECONDS)
        raw = json.dumps(fingerprint) + str(window)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def is_new(self, events):
        key = self._key(events)
        return key not in self.cache, key

    def register(self, key, events):
        self.counter += 1
        inc = Incident(f"INC-{self.counter:04d}", key, events)
        self.cache[key] = (time.time(), inc)
        return inc

    def cleanup(self):
        now = time.time()
        self.cache = {k: v for k, v in self.cache.items() if now - v[0] < 300}

ACTIONABLE = {
    "BackOff", "Failed", "ErrImagePull", "ImagePullBackOff",
    "CrashLoopBackOff", "OOMKilled", "FailedScheduling",
}

def is_actionable(event):
    return event.get("reason") in ACTIONABLE

def format_event(e):
    obj = e["object"]
    return {
        "reason": obj.reason or "unknown",
        "message": obj.message or "",
        "name": obj.involved_object.name,
        "namespace": obj.metadata.namespace,
        "kind": obj.involved_object.kind,
        "time": str(obj.last_timestamp or datetime.now(timezone.utc)),
    }

def k8s():
    try:
        config.load_incluster_config()
    except:
        config.load_kube_config()
    return client.CoreV1Api()

SYSTEM = """
You are a Kubernetes SRE engine.
Rules: Only use provided events. Do not guess. If unknown say "unknown".
Output MUST be JSON only.

Format:
{
  "severity": "critical|high|medium|low",
  "confidence": 0-1,
  "what_happened": "...",
  "why_it_happened": "...",
  "actions": []
}
"""

def call_llm(events):
    payload = {"model": MODEL, "system": SYSTEM, "prompt": json.dumps(events, indent=2), "stream": False}
    try:
        r = requests.post(OLLAMA_URL, json=payload, timeout=60)
        r.raise_for_status()
        text = r.json().get("response", "").strip()
        try:
            return json.loads(text)
        except:
            return {"severity": "unknown", "confidence": 0.0, "what_happened": text[:300], "why_it_happened": "parse_error", "actions": []}
    except Exception as e:
        return {"severity": "unknown", "confidence": 0.0, "what_happened": str(e)[:300], "why_it_happened": "llm_error", "actions": []}

def notify_webhook(inc):
    if not WEBHOOK_URL:
        return
    r = inc.report
    color = "#ff0000" if r.get("severity") == "critical" else "#ffa500"
    payload = {
        "text": f"[{inc.id}] {r.get('what_happened', '')[:200]}",
        "attachments": [{"color": color, "fields": [
            {"title": "Why", "value": r.get("why_it_happened", "unknown"), "short": False},
            {"title": "Actions", "value": "\n".join(f"- {a}" if isinstance(a, str) else a.get("action", str(a)) for a in r.get("actions", [])), "short": False},
            {"title": "Severity", "value": r.get("severity", "unknown"), "short": True},
            {"title": "Confidence", "value": str(r.get("confidence", 0)), "short": True},
        ]}],
    }
    try:
        requests.post(WEBHOOK_URL, json=payload, timeout=10)
    except:
        pass

def print_incident(inc):
    r = inc.report
    print(f"\n{'='*60}")
    print(f"[{inc.id}] {r.get('severity','?').upper()} | confidence={r.get('confidence',0)}")
    print(f"What: {r.get('what_happened','')}")
    print(f"Why: {r.get('why_it_happened','')}")
    for a in r.get("actions", []):
        print(f"  → {a if isinstance(a,str) else a.get('action','?')}")
    print(f"{'='*60}")

class MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            body = json.dumps({"status": "ok"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)

        elif self.path == "/incidents":
            body = json.dumps([i.to_dict() for i in incidents], indent=2).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)

        elif self.path == "/metrics":
            total = len(incidents)
            by_severity = {}
            for i in incidents:
                s = ((i.report or {}).get("severity", "unknown") or "unknown").lower()
                by_severity[s] = by_severity.get(s, 0) + 1

            def sanitize(v):
                return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")[:200]

            lines = [
                "# HELP ai_sre_incidents_total Total incidents analyzed",
                "# TYPE ai_sre_incidents_total gauge",
                f'ai_sre_incidents_total {total}',
                "# HELP ai_sre_incidents_by_severity Incidents by severity",
                "# TYPE ai_sre_incidents_by_severity gauge",
            ]
            for sev, count in by_severity.items():
                lines.append(f'ai_sre_incidents_by_severity{{severity="{sev.lower()}"}} {count}')

            lines.append("# HELP ai_sre_llm_calls_total Total LLM calls made")
            lines.append("# TYPE ai_sre_llm_calls_total counter")
            lines.append(f'ai_sre_llm_calls_total {total}')

            lines.append("# HELP ai_sre_incident_info Incident details")
            lines.append("# TYPE ai_sre_incident_info gauge")
            for inc in incidents[-20:]:
                r = inc.report or {}
                what = sanitize(r.get("what_happened", ""))
                why = sanitize(r.get("why_it_happened", ""))
                sev = (r.get("severity", "unknown") or "unknown").lower()
                lines.append(f'ai_sre_incident_info{{id="{inc.id}",severity="{sev}",what="{what}",why="{why}"}} 1')

            body = "\n".join(lines).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(body)

        else:
            self.send_error(404)

    def log_message(self, format, *args):
        pass

def run_metrics():
    server = HTTPServer(("0.0.0.0", METRICS_PORT), MetricsHandler)
    print(f"[Metrics] Listening on :{METRICS_PORT}")
    server.serve_forever()

def run():
    global incidents
    v1 = k8s()
    w = watch.Watch()
    tracker = IncidentTracker()
    window = []

    print("[AI-SRE] Engine started")
    threading.Thread(target=run_metrics, daemon=True).start()

    for event in w.stream(v1.list_event_for_all_namespaces):
        evt = format_event(event)
        if not is_actionable(evt):
            continue
        window.append(evt)
        window = window[-50:]

        if len(window) < 5:
            continue

        tracker.cleanup()
        new, key = tracker.is_new(window)
        if not new:
            continue

        inc = tracker.register(key, list(window))
        window.clear()
        inc.report = call_llm(inc.events)
        inc.state = State.ANALYZED
        incidents.append(inc)
        incidents = incidents[-50:]
        print_incident(inc)
        notify_webhook(inc)
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    run()
