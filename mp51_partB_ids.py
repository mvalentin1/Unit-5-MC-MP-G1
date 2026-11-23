"""Mini Project 5.1 - Part B: rule-based signaling-plane anomaly detection over a synthetic log.
Standard library only; software-only, no real network data."""
import random

ALLOWED = {"attach", "location_update", "auth_request", "detach"}
REQUIRED = ("timestamp", "subscriber_id", "event_type", "country")
COUNTRIES = ["RW", "UG", "KE", "TZ", "ZA", "US", "FR", "IN"]

def generate_signaling_log(n, seed=42, n_subs=40, legit_border_hops=2, inject=True):
    """Return (events, ground_truth). Events are in ARRIVAL order. ground_truth maps idx -> label."""
    rng = random.Random(seed)
    subs = [f"SUB{1000+i}" for i in range(n_subs)]
    home = {s: rng.choice(COUNTRIES) for s in subs}
    clock = {s: rng.randint(0, 3600) for s in subs}
    events = []
    for _ in range(n):                                   # plausible, internally consistent traffic
        s = rng.choice(subs)
        clock[s] += rng.randint(900, 7200)               # 15 min - 2 h between events
        events.append({"timestamp": clock[s], "subscriber_id": s,
                       "event_type": rng.choice(["attach", "location_update", "auth_request", "detach"]),
                       "country": home[s]})
    truth = {}
    if not inject: return events, truth
    base = max(e["timestamp"] for e in events) + 10_000
    # (a) implausible roaming: RW then US 20 minutes later
    events += [{"timestamp": base, "subscriber_id": "SUB_A", "event_type": "location_update", "country": "RW"},
               {"timestamp": base + 1200, "subscriber_id": "SUB_A", "event_type": "location_update", "country": "US"}]
    truth[len(events)-1] = "implausible_travel"
    # (b) malformed messages
    events.append({"timestamp": base + 50, "subscriber_id": "SUB_B", "event_type": "attach"})            # missing country
    truth[len(events)-1] = "schema"
    events.append({"timestamp": base + 60, "subscriber_id": "SUB_C", "event_type": "sms_intercept", "country": "FR"})
    truth[len(events)-1] = "schema"
    # (c) auth_request burst: 25 requests in 60 s
    for i in range(25):
        events.append({"timestamp": base + 100 + i*2, "subscriber_id": "SUB_D", "event_type": "auth_request", "country": "KE"})
        truth[len(events)-1] = "burst"
    # (d) non-monotonic timestamp (arrives later but stamped earlier)
    events.append({"timestamp": base + 500, "subscriber_id": "SUB_E", "event_type": "attach", "country": "IN"})
    events.append({"timestamp": base + 100, "subscriber_id": "SUB_E", "event_type": "location_update", "country": "IN"})
    truth[len(events)-1] = "non_monotonic"
    # (e) LEGITIMATE border hops (benign): Rwanda->Uganda in ~75 min by road/air - tests false positives
    for j in range(legit_border_hops):
        s = f"SUB_BORDER{j}"
        events.append({"timestamp": base + 2000 + j*50, "subscriber_id": s, "event_type": "location_update", "country": "RW"})
        events.append({"timestamp": base + 2000 + j*50 + 4500, "subscriber_id": s, "event_type": "location_update", "country": "UG"})
        truth[len(events)-1] = "benign_border_hop"
    # (f) SLOW real attack missed by a short threshold: RW -> FR in 3 h (physically impossible by commercial speed? ~ 8 h flight)
    events.append({"timestamp": base + 3000, "subscriber_id": "SUB_F", "event_type": "location_update", "country": "RW"})
    events.append({"timestamp": base + 3000 + 3*3600, "subscriber_id": "SUB_F", "event_type": "location_update", "country": "FR"})
    truth[len(events)-1] = "implausible_travel"
    return events, truth

def detect(events, min_travel_s=2*3600, burst_window=60, burst_max=10):
    """Return list of (event_index, rule, detail)."""
    flags = []
    valid = lambda e: all(k in e for k in REQUIRED) and e["event_type"] in ALLOWED
    # Rule 2: schema / conformance
    for i, e in enumerate(events):
        missing = [k for k in REQUIRED if k not in e]
        if missing: flags.append((i, "SCHEMA", f"missing field(s): {missing}"))
        elif e["event_type"] not in ALLOWED: flags.append((i, "SCHEMA", f"invalid event_type '{e['event_type']}'"))
    # Rule 1: implausible travel (sort per subscriber by time, compare consecutive entries)
    by_sub = {}
    for i, e in enumerate(events):
        if valid(e): by_sub.setdefault(e["subscriber_id"], []).append((e["timestamp"], i, e))
    for s, lst in by_sub.items():
        lst.sort(key=lambda t: t[0])
        for (t0, i0, e0), (t1, i1, e1) in zip(lst, lst[1:]):
            if e0["country"] != e1["country"] and (t1 - t0) < min_travel_s:
                flags.append((i1, "TRAVEL", f"{e0['country']}->{e1['country']} in {(t1-t0)//60} min (< {min_travel_s//60} min)"))
    # Rule 3: auth_request rate per subscriber (sliding window)
    auth = {}
    for i, e in enumerate(events):
        if valid(e) and e["event_type"] == "auth_request": auth.setdefault(e["subscriber_id"], []).append((e["timestamp"], i))
    for s, lst in auth.items():
        lst.sort(); lo = 0; flagged = False
        for hi in range(len(lst)):
            while lst[hi][0] - lst[lo][0] > burst_window: lo += 1
            if hi - lo + 1 > burst_max and not flagged:
                flags.append((lst[hi][1], "RATE", f"{hi-lo+1} auth_requests in {burst_window}s (> {burst_max})")); flagged = True
    # Rule 4 (Task 6): non-monotonic timestamps in ARRIVAL order per subscriber
    last = {}
    for i, e in enumerate(events):
        if not valid(e): continue
        s = e["subscriber_id"]
        if s in last and e["timestamp"] < last[s]:
            flags.append((i, "NON_MONOTONIC", f"timestamp {e['timestamp']} < previous {last[s]}"))
        last[s] = max(last.get(s, 0), e["timestamp"])
    return sorted(flags)

RULE_FOR = {"implausible_travel": "TRAVEL", "schema": "SCHEMA", "burst": "RATE", "non_monotonic": "NON_MONOTONIC"}

def score(flags, truth):
    flagged_idx = {i for i, _, _ in flags}
    real = {i for i, lab in truth.items() if lab != "benign_border_hop"}
    benign = {i for i, lab in truth.items() if lab == "benign_border_hop"}
    tp = len(real & flagged_idx); fn = len(real - flagged_idx)
    fp_benign = len(benign & flagged_idx)
    fp_other = len(flagged_idx - set(truth))             # flags on ordinary generated events
    return tp, fn, fp_benign + fp_other, fp_other

if __name__ == "__main__":
    events, truth = generate_signaling_log(300)
    print(f"Generated {len(events)} events ({len(truth)} labelled anomalies/edge cases)\n")
    flags = detect(events)
    print("=== Flagged entries (threshold = 120 min, burst > 10 in 60 s) ===")
    seen_burst = False
    for i, rule, detail in flags:
        print(f"[{rule:13}] idx={i:3} {events[i]}  -> {detail}")
    print("\n=== Summary vs injected anomalies (extended injected set) ===")
    burst_idx = [i for i, l in truth.items() if l == "burst"]
    burst_hit = any(r == "RATE" and j in burst_idx for j, r, _ in flags)
    print(f"idx={burst_idx[0]}-{burst_idx[-1]} burst (25 auth_requests/60 s) -> {'CAUGHT (one RATE flag on the 11th request)' if burst_hit else 'MISSED'}")
    for idx, lab in sorted(truth.items()):
        if lab == "burst": continue
        hit = [r for j, r, _ in flags if j == idx]
        want = RULE_FOR.get(lab)
        status = ("CAUGHT" if want in hit else "MISSED") if lab != "benign_border_hop" else ("FALSE POSITIVE" if hit else "correctly passed")
        if lab == "burst" and want not in hit: status = "(covered by single burst flag)"
        print(f"idx={idx:3} {lab:20} -> {status}")
    tp, fn, fp, fp_other = score(flags, truth)
    print(f"\nOrdinary-traffic events flagged (false positives on clean data): {fp_other}")

    print("\n=== Lab Task 5: tuning the travel threshold on a larger log (2000 events, 5 seeds) ===")
    print("threshold | caught travel anomalies | missed | false positives (benign border hops)")
    for thr_min in (30, 60, 90, 120, 240, 480):
        c = m = f = 0
        for seed in range(5):
            ev, tr = generate_signaling_log(2000, seed=seed, legit_border_hops=5)
            fl = detect(ev, min_travel_s=thr_min*60, burst_max=10)
            ti = {i for i, l in tr.items() if l == "implausible_travel"}
            bi = {i for i, l in tr.items() if l == "benign_border_hop"}
            hit = {i for i, r, _ in fl if r == "TRAVEL"}
            c += len(ti & hit); m += len(ti - hit); f += len(bi & hit)
        print(f"{thr_min:4} min  | {c:3} / {c+m:<3}               | {m:3}    | {f:3} / {5*5}")
    print("\n=== Lab Task 2: rate rule on burst (re-run with rule thresholds) ===")
    for bm in (5, 10, 30):
        fl = [x for x in detect(events, burst_max=bm) if x[1] == "RATE"]
        print(f"burst_max={bm:2}: {len(fl)} RATE flag(s)", [events[i]['subscriber_id'] for i,_,_ in fl])
