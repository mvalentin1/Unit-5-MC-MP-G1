"""Mini Project 5.3 - Privacy-compliance checklist tool (GDPR, CCPA/CPRA, LGPD, DPDP Act).
Rules are authored from Unit 5, Section 5.7 only. Standard library only. Hypothetical app: "StrideFit"."""

SENSITIVE = {"precise_location", "biometric_health"}   # 5.7: GDPR treats location/metadata as sensitive;
                                                      # CPRA lists precise geolocation as SPI; LGPD heightened scrutiny of geolocation

# ---------------- app data profile (sample data) ----------------
APP = "StrideFit - ad-supported fitness tracker (users in EU, California, Brazil, India)"
PRACTICES = [
 dict(id="P1", category="precise_location", purpose="GPS route tracking + ad targeting", consent="bundled_terms",
      legal_basis="consent", retention_months=36, third_party="sold_to_ad_networks", opt_out_link=False,
      limit_sensitive_option=False, notice_at_collection=True, markets={"EU","CA","BR","IN"}),
 dict(id="P2", category="contacts", purpose="friend finder", consent="opt_in_dialog",
      legal_basis="consent", retention_months=None, third_party="none", opt_out_link=False,
      limit_sensitive_option=False, notice_at_collection=True, markets={"EU","CA","IN"}),
 dict(id="P3", category="advertising_id", purpose="personalised ads", consent="opt_out_setting",
      legal_basis="legitimate_interest", retention_months=12, third_party="shared_with_ad_networks", opt_out_link=True,
      limit_sensitive_option=False, notice_at_collection=True, markets={"EU","CA","BR","IN"}),
 dict(id="P4", category="usage_analytics", purpose="product improvement", consent="none",
      legal_basis=None, retention_months=24, third_party="processor_only", opt_out_link=False,
      limit_sensitive_option=False, notice_at_collection=False, markets={"EU","CA","BR","IN"}),
 dict(id="P5", category="biometric_health", purpose="heart-rate/sleep insights; insurer wellness partner", consent="opt_in_dialog",
      legal_basis="consent", retention_months=60, third_party="sold_to_insurer_partner", opt_out_link=False,
      limit_sensitive_option=False, notice_at_collection=True, markets={"CA"}),   # US-only feature
]
APP_WIDE = dict(rights_access=True, rights_erasure=True, rights_portability=False, rights_correction=True,
                breach_notice_authority_72h=True, breach_notice_anpd_process=False,
                breach_notice_dpb=False, security_safeguards=True, grievance_redressal=False)

# ---------------- rule helpers: each returns (ok, reason) ----------------
shared = lambda p: p["third_party"] not in ("none", "processor_only")

def gdpr(p):
    r = []
    if p["legal_basis"] is None: r.append("G1 no lawful basis declared")
    elif p["legal_basis"] == "consent" and p["consent"] != "opt_in_dialog": r.append(f"G1 consent not affirmative opt-in (uses {p['consent']})")
    if p["category"] in SENSITIVE and p["consent"] != "opt_in_dialog": r.append("G2 sensitive data (location/biometric) lacks explicit opt-in")
    if p["retention_months"] is None: r.append("G3 no defined retention limit (data minimisation/retention)")
    if shared(p) and p["consent"] not in ("opt_in_dialog",) and p["legal_basis"] == "consent": r.append("G4 third-party sharing not covered by valid consent")
    return r
def ccpa(p):
    r = []
    if shared(p) and not p["opt_out_link"]: r.append("C1 sale/sharing without a 'Do Not Sell or Share' opt-out")
    if p["category"] in SENSITIVE and not p["limit_sensitive_option"]: r.append("C2 sensitive personal information (e.g. precise geolocation) lacks 'limit use' option")
    if not p["notice_at_collection"]: r.append("C3 no notice at collection of categories/purposes (right to know)")
    return r
def lgpd(p):
    r = []
    if p["legal_basis"] is None: r.append("L1 no valid legal basis")
    elif p["legal_basis"] == "consent" and p["consent"] != "opt_in_dialog": r.append("L1 consent invalid (bundled/implied, not specific)")
    if p["category"] in SENSITIVE and p["consent"] != "opt_in_dialog": r.append("L2 sensitive/geolocation needs heightened basis")
    if p["retention_months"] is None: r.append("L3 no retention/deletion limit")
    return r
def dpdp(p):
    r = []
    if not p["notice_at_collection"]: r.append("D1 no clear notice to Data Principal")
    if p["consent"] in ("bundled_terms", "none") and p["legal_basis"] != "legitimate_interest": r.append("D2 neither valid consent nor defined legitimate use")
    if shared(p) and not p["notice_at_collection"]: r.append("D3 sharing not notified")
    return r

FRAMEWORKS = {"GDPR": ("EU", gdpr), "CCPA/CPRA": ("CA", ccpa), "LGPD": ("BR", lgpd), "DPDP": ("IN", dpdp)}

def app_wide_gaps(a):
    return {"GDPR": [m for ok, m in [(a["rights_access"] and a["rights_erasure"] and a["rights_portability"], "GDPR: access/erasure/portability rights incomplete (no portability export)"),
                                      (a["breach_notice_authority_72h"], "GDPR: no 72-hour breach notification process")] if not ok],
            "CCPA/CPRA": [m for ok, m in [(a["rights_access"] and a["rights_erasure"] and a["rights_correction"], "CPRA: know/delete/correct rights incomplete")] if not ok],
            "LGPD": [m for ok, m in [(a["rights_portability"], "LGPD: portability right not supported"),
                                      (a["breach_notice_anpd_process"], "LGPD: no ANPD-specific breach-reporting process")] if not ok],
            "DPDP": [m for ok, m in [(a["breach_notice_dpb"], "DPDP: no breach notification to Data Protection Board"),
                                      (a["security_safeguards"], "DPDP: no reasonable security safeguards"),
                                      (a["grievance_redressal"], "DPDP: no grievance-redressal mechanism for Data Principals")] if not ok]}

def run():
    print("APP:", APP, "\n")
    hdr = f"{'Practice':34}" + "".join(f"{f:12}" for f in FRAMEWORKS)
    print(hdr); print("-" * len(hdr))
    gaps = {f: [] for f in FRAMEWORKS}
    for p in PRACTICES:
        row = f"{p['id']+' '+p['category']:34}"
        for f, (mkt, fn) in FRAMEWORKS.items():
            if mkt not in p["markets"]: row += f"{'N/A':12}"; continue
            g = fn(p)
            row += f"{'GAP('+str(len(g))+')' if g else 'compliant':12}"
            for reason in g: gaps[f].append((p["id"], p["category"], reason))
        print(row)
    aw = app_wide_gaps(APP_WIDE)
    print("\nApp-wide controls:", {f: ("GAP" if v else "ok") for f, v in aw.items()})
    print("\n" + "=" * 70 + "\nGAP REPORT PER FRAMEWORK\n" + "=" * 70)
    for f in FRAMEWORKS:
        print(f"\n## {f}  ({len(gaps[f])} practice-level gaps, {len(aw[f])} app-wide gaps)")
        for pid, cat, reason in gaps[f]: print(f"  - {pid} [{cat}] {reason}")
        for m in aw[f]: print(f"  - [app-wide] {m}")
    total = sum(len(v) for v in gaps.values()) + sum(len(v) for v in aw.values())
    # priority: sensitive categories and third-party sharing first
    prio = {}
    for p in PRACTICES:
        n_fw = len({f for f in FRAMEWORKS for (pid, _, _) in gaps[f] if pid == p["id"]})
        if n_fw: prio[p["id"]] = n_fw + (2 if p["category"] in SENSITIVE else 0) + (2 if shared(p) else 0)
    print("\nTotal gaps:", total)
    print("Remediation priority (score = #framework gaps + 2 if sensitive + 2 if sold/shared):")
    for pid, s in sorted(prio.items(), key=lambda t: -t[1]):
        p = next(x for x in PRACTICES if x["id"] == pid); print(f"  {pid} {p['category']:18} score={s}")

if __name__ == "__main__":
    run()
