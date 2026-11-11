"""Reproduce the UNIQUE-constraint 500 under CONCURRENT artifact deletes.

Logs showed three deletions inside the same second (12:55:03), each triggering
analyze_project -> seed_iocs on a single shared sqlite connection with no lock.
Sequential deletes pass; concurrent ones can race.
"""
import json
import threading
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:8088"


def call(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        BASE + path, data=data, method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:200]
    except Exception as e:
        return -1, repr(e)


# Create several artifacts so we can delete them at once.
ids = []
for i in range(4):
    ev = [{"@timestamp": "2026-06-03T1%d:00:00Z" % i, "host": "RACE-HOST",
           "source": "edr", "event_id": 1, "event_type": "process_create",
           "user_name": "race", "process_name": r"C:\Windows\System32\cmd.exe",
           "parent_process": r"C:\Windows\explorer.exe"}]
    st, res = call("POST", "/api/ingest/text",
                   {"text": json.dumps(ev), "filename": "race-%d.json" % i,
                    "source_type": "edr"})
    if st == 200:
        ids.append(res.get("artifact_id"))

print("artifacts to delete concurrently:", ids)

results = {}


def worker(aid):
    results[aid] = call("DELETE", "/api/artifacts/%d" % aid)


threads = [threading.Thread(target=worker, args=(a,)) for a in ids]
for t in threads:
    t.start()
for t in threads:
    t.join()

fails = 0
for aid in ids:
    st, body = results.get(aid, (None, None))
    ok = st == 200
    fails += 0 if ok else 1
    print("  artifact %-4s -> HTTP %s" % (aid, st))
    if not ok:
        print("      body:", str(body)[:180])

print()
print("VERDICT:", "BUG REPRODUCED (%d/%d failed)" % (fails, len(ids))
      if fails else "no failure this run")
