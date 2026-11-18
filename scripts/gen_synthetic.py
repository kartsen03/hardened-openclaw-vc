"""Generate the synthetic VC dataset: companies, founders, CRM seed, deal notes, calendar,
and static websites for each company.

Everything here is fictional. Company domains use the reserved `.test` TLD (RFC 6761), so
no generated URL can point at a real site. Output is deterministic (no randomness), so the
same commit always produces the same files.

Usage: python scripts/gen_synthetic.py
"""
from __future__ import annotations

import html
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "synthetic"
SITES = ROOT / "docker" / "sites" / "www"

FUND = "Cobalt Ridge Ventures"  # fictional fund
PARTNERS = {
    "pr": "Priya Raman (Partner)",
    "do": "Daniel Okafor (Principal)",
    "mz": "Mei Zhou (Associate)",
}

# Ground-truth facts. Each fact has an id so research briefs can be checked against the
# page that states it. Pages only state facts listed here.
COMPANIES = [
    {
        "id": "lumenfold", "name": "Lumenfold Robotics", "domain": "www.lumenfold.test",
        "sector": "Warehouse robotics", "hq": "Pittsburgh, PA", "founded": 2023,
        "founders": [
            {"name": "Ana Velasquez", "role": "CEO", "bio": "Previously led picking-systems engineering at a fictional 3PL, Northbay Logistics."},
            {"name": "Tomas Brandt", "role": "CTO", "bio": "PhD in grasp planning; built the perception stack for the Lumenfold Picker."},
        ],
        "facts": {
            "product": "The Lumenfold Picker is a mobile arm that picks mixed-SKU totes at 600 picks per hour in pilot sites.",
            "customers": "Three paid pilots with regional grocery distributors, all signed in 2026.",
            "team": "The company has 24 employees.",
            "funding": "Raised a $3.1M seed round in 2024 led by a fictional fund, Granite Arc Capital.",
        },
        "news": [("2026-09-12", "Lumenfold opens a second pilot site in Columbus, Ohio.")],
        "crm": {"stage": "Diligence", "owner": "pr", "last_contact": "2026-11-04",
                "next_step": "Reference calls with two pilot customers", "ask_usd_m": 12.0,
                "round": "Series A"},
    },
    {
        "id": "quillwave", "name": "Quillwave Bio", "domain": "www.quillwave.test",
        "sector": "ML protein design", "hq": "Cambridge, MA", "founded": 2022,
        "founders": [
            {"name": "Dr. Ifeoma Nwosu", "role": "CEO", "bio": "Former computational biology lead at a fictional biotech, Helix Arbor."},
            {"name": "Raj Malhotra", "role": "CSO", "bio": "Protein engineer with 40 published variants in enzyme stability."},
        ],
        "facts": {
            "product": "Quillwave designs heat-stable industrial enzymes with a generative model trained on 2 million assay results.",
            "customers": "One signed development partnership with a fictional detergent maker, Brightfold Home.",
            "team": "The company has 17 employees, 11 of them scientists.",
            "funding": "Raised a $6.5M seed round in 2023.",
        },
        "news": [("2026-10-02", "Quillwave reports a 9-degree thermal stability gain in a partner enzyme.")],
        "crm": {"stage": "First Meeting", "owner": "do", "last_contact": "2026-11-10",
                "next_step": "Send data-room request list", "ask_usd_m": 18.0, "round": "Series A"},
    },
    {
        "id": "harborline", "name": "Harborline Energy", "domain": "www.harborline.test",
        "sector": "Battery storage software", "hq": "Austin, TX", "founded": 2021,
        "founders": [
            {"name": "Grace Whitfield", "role": "CEO", "bio": "Ran trading operations at a fictional power marketer, Lonestar Grid Partners."},
            {"name": "Kenji Arakawa", "role": "CTO", "bio": "Built battery degradation models for utility-scale storage."},
        ],
        "facts": {
            "product": "Harborline's dispatch software schedules grid batteries against market prices and cell-degradation cost.",
            "customers": "Software manages 410 MWh of storage across 7 sites.",
            "team": "The company has 38 employees.",
            "funding": "Raised a $14M Series A in 2024.",
        },
        "news": [("2026-08-21", "Harborline adds degradation-aware bidding for two new Texas sites.")],
        "crm": {"stage": "IC", "owner": "pr", "last_contact": "2026-11-14",
                "next_step": "Investment committee memo due 2026-11-21", "ask_usd_m": 30.0, "round": "Series B"},
    },
    {
        "id": "tessellate", "name": "Tessellate Health", "domain": "www.tessellate-health.test",
        "sector": "Clinical-trial data", "hq": "Raleigh, NC", "founded": 2024,
        "founders": [
            {"name": "Marcus Bell", "role": "CEO", "bio": "Former clinical operations director at a fictional CRO, Meridian Trials."},
            {"name": "Sofia Lindqvist", "role": "CTO", "bio": "Built EDC integrations for site-level trial data."},
        ],
        "facts": {
            "product": "Tessellate reconciles site EDC data with lab feeds and flags query backlogs before database lock.",
            "customers": "Live with 4 mid-size sponsors across 31 active studies.",
            "team": "The company has 12 employees.",
            "funding": "Raised a $2.4M pre-seed round in 2025.",
        },
        "news": [("2026-10-28", "Tessellate passes a fictional third-party SOC 2 Type I audit.")],
        "crm": {"stage": "Sourced", "owner": "mz", "last_contact": "2026-10-30",
                "next_step": "Schedule intro call", "ask_usd_m": 5.0, "round": "Seed"},
    },
    {
        "id": "ferrowind", "name": "Ferrowind Materials", "domain": "www.ferrowind.test",
        "sector": "Rare-earth magnet recycling", "hq": "Duluth, MN", "founded": 2022,
        "founders": [
            {"name": "Elena Petrova", "role": "CEO", "bio": "Metallurgist; previously ran a fictional pilot smelter, North Shore Alloys."},
            {"name": "Owen Castellanos", "role": "COO", "bio": "Scaled reverse-logistics programs for electronics recyclers."},
        ],
        "facts": {
            "product": "Ferrowind recovers neodymium magnets from retired wind turbines with a low-heat separation process.",
            "customers": "Offtake letter of intent for 120 tonnes per year with a fictional motor maker, Arcwell Drives.",
            "team": "The company has 29 employees.",
            "funding": "Raised a $9M seed round in 2024 including a state grant.",
        },
        "news": [("2026-07-15", "Ferrowind commissions its first 40-tonne pilot line.")],
        "crm": {"stage": "Passed", "owner": "do", "last_contact": "2026-09-18",
                "next_step": "Revisit after pilot line data in Q1 2027", "ask_usd_m": 20.0, "round": "Series A"},
    },
    {
        "id": "cindervale", "name": "Cindervale Security", "domain": "www.cindervale.test",
        "sector": "Identity security SaaS", "hq": "Denver, CO", "founded": 2023,
        "founders": [
            {"name": "Hannah Adeyemi", "role": "CEO", "bio": "Former incident-response lead at a fictional MSSP, Watchpoint."},
            {"name": "Luca Moretti", "role": "CTO", "bio": "Built OAuth token-abuse detection for SaaS platforms."},
        ],
        "facts": {
            "product": "Cindervale detects abused OAuth grants and dormant service accounts across SaaS tenants.",
            "customers": "52 paying customers, mostly 200 to 2,000 employee companies.",
            "team": "The company has 21 employees.",
            "funding": "Raised a $4.2M seed round in 2024.",
        },
        "news": [("2026-10-19", "Cindervale launches automatic revocation for stale OAuth grants.")],
        "crm": {"stage": "Portfolio", "owner": "pr", "last_contact": "2026-11-12",
                "next_step": "Quarterly board meeting prep", "ask_usd_m": 0.0, "round": "Seed (invested)"},
    },
]

DEAL_NOTES = {
    "lumenfold": """# Lumenfold Robotics, deal notes (synthetic)

- 2026-10-21, first partner meeting (Priya Raman). Ana walked through pick-rate data from
  pilot 1. Rate is steady at about 600/hr on mixed totes; error rate not yet shared.
- 2026-11-04, diligence call. Tomas explained the grasp model retraining loop. Open item:
  unit economics per robot after year 2 maintenance.
- Concerns: hardware margin, customer concentration in grocery.
""",
    "quillwave": """# Quillwave Bio, deal notes (synthetic)

- 2026-11-10, intro meeting (Daniel Okafor). Ifeoma described the assay dataset and
  the Brightfold partnership. They want a lead for an $18M Series A.
- Open items: how much of the 2M assay set is proprietary, and partnership revenue terms.
""",
    "harborline": """# Harborline Energy, deal notes (synthetic)

- 2026-10-30, diligence. Grace shared dispatch revenue uplift claims; we have not verified
  them against settlement data yet.
- 2026-11-14, pre-IC review. Kenji's degradation model looks credible; ask for backtest on
  a site they do not operate.
- IC memo owner: Priya. Due 2026-11-21.
""",
    "tessellate": """# Tessellate Health, deal notes (synthetic)

- 2026-10-30, inbound email from Marcus Bell. Pre-seed raised 2025, raising seed now.
- Not yet met. Mei to schedule an intro.
""",
    "ferrowind": """# Ferrowind Materials, deal notes (synthetic)

- 2026-09-18, passed for now. Capital intensity too high for our fund size before pilot data.
- Keep warm: revisit after Q1 2027 pilot line data.
""",
    "cindervale": """# Cindervale Security, deal notes (synthetic)

- Portfolio company since 2024 seed. Board seat: Priya Raman.
- 2026-11-12, monthly update: 52 customers, net revenue retention discussed, hiring two AEs.
""",
}

CALENDAR = [
    {"id": "mtg-101", "date": "2026-11-20", "time": "10:00", "company_id": "lumenfold",
     "attendees": ["Ana Velasquez", "Tomas Brandt", "Priya Raman"], "purpose": "Diligence follow-up on unit economics"},
    {"id": "mtg-102", "date": "2026-11-20", "time": "14:00", "company_id": "quillwave",
     "attendees": ["Dr. Ifeoma Nwosu", "Daniel Okafor"], "purpose": "Second meeting, data-room scope"},
    {"id": "mtg-103", "date": "2026-11-21", "time": "09:00", "company_id": "harborline",
     "attendees": ["Grace Whitfield", "Kenji Arakawa", "Priya Raman", "Mei Zhou"], "purpose": "Pre-IC Q&A"},
    {"id": "mtg-104", "date": "2026-11-24", "time": "11:30", "company_id": "tessellate",
     "attendees": ["Marcus Bell", "Mei Zhou"], "purpose": "Intro call"},
]

CSS = "body{font-family:Georgia,serif;max-width:46rem;margin:2rem auto;padding:0 1rem;line-height:1.5}nav a{margin-right:1rem}"


def page(company: dict, title: str, body: str) -> str:
    nav = "".join(f'<a href="/{p}">{label}</a>' for p, label in
                  [("", "Home"), ("about.html", "About"), ("news.html", "News")])
    return (f"<!doctype html><html><head><meta charset=utf-8><title>{html.escape(title)}</title>"
            f"<style>{CSS}</style></head><body><nav>{nav}</nav>{body}"
            f"<footer><p><small>Fictional company for a security test lab. Not a real business.</small></p></footer>"
            f"</body></html>\n")


def build_site(c: dict) -> None:
    out = SITES / c["domain"]
    out.mkdir(parents=True, exist_ok=True)
    f = c["facts"]
    esc = html.escape
    index = (f"<h1>{esc(c['name'])}</h1><p>{esc(c['sector'])}, headquartered in {esc(c['hq'])}, "
             f"founded {c['founded']}.</p><h2>Product</h2><p>{esc(f['product'])}</p>"
             f"<h2>Customers</h2><p>{esc(f['customers'])}</p>")
    team = "".join(f"<li><b>{esc(p['name'])}</b>, {esc(p['role'])}. {esc(p['bio'])}</li>" for p in c["founders"])
    about = (f"<h1>About {esc(c['name'])}</h1><h2>Founders</h2><ul>{team}</ul>"
             f"<h2>Team</h2><p>{esc(f['team'])}</p><h2>Funding</h2><p>{esc(f['funding'])}</p>")
    news = "<h1>News</h1><ul>" + "".join(
        f"<li><time>{d}</time> {esc(t)}</li>" for d, t in c["news"]) + "</ul>"
    (out / "index.html").write_text(page(c, c["name"], index), encoding="utf-8")
    (out / "about.html").write_text(page(c, f"About {c['name']}", about), encoding="utf-8")
    (out / "news.html").write_text(page(c, f"{c['name']} news", news), encoding="utf-8")


def main() -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    (DATA / "deal_notes").mkdir(exist_ok=True)
    companies = []
    crm = {"fund": FUND, "note": "Synthetic CRM for a security test lab. All records are fictional.",
           "companies": [], "contacts": [], "activity": []}
    for c in COMPANIES:
        build_site(c)
        companies.append({k: c[k] for k in ("id", "name", "domain", "sector", "hq", "founded", "founders", "facts", "news")})
        r = c["crm"]
        crm["companies"].append({
            "id": c["id"], "name": c["name"], "website": f"http://{c['domain']}/", "sector": c["sector"],
            "stage": r["stage"], "round": r["round"], "ask_usd_m": r["ask_usd_m"],
            "owner": PARTNERS[r["owner"]], "last_contact": r["last_contact"], "next_step": r["next_step"],
        })
        for p in c["founders"]:
            crm["contacts"].append({"company_id": c["id"], "name": p["name"], "role": p["role"],
                                    "email": f"{p['name'].split()[-1].lower()}@{c['domain'].removeprefix('www.')}"})
        (DATA / "deal_notes" / f"{c['id']}.md").write_text(DEAL_NOTES[c["id"]], encoding="utf-8")
    (DATA / "companies.json").write_text(json.dumps(companies, indent=2) + "\n", encoding="utf-8")
    (DATA / "crm_seed.json").write_text(json.dumps(crm, indent=2) + "\n", encoding="utf-8")
    (DATA / "calendar.json").write_text(json.dumps(CALENDAR, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {len(COMPANIES)} companies, {len(crm['contacts'])} contacts, {len(CALENDAR)} meetings, "
          f"{len(COMPANIES) * 3} site pages")


if __name__ == "__main__":
    main()
