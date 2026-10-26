"""
Active Directory Defensive Lab (Simulation)
IBM SkillsBuild Cyber Security 2026 project

This project uses fictional sample events to demonstrate defensive triage.
It does NOT connect to Active Directory, perform Kerberoasting, or modify GPOs.
Run: python Paru_Active_Directory_Defensive_Lab.py
"""
from collections import Counter
from datetime import datetime
import json
from pathlib import Path

SAMPLE_EVENTS = [
    {
        "timestamp": "2026-10-20T09:14:00",
        "event_id": 4769,
        "account": "svc_backup",
        "service": "MSSQLSvc/DB01.example.test",
        "ticket_encryption": "RC4",
        "source_host": "WS-014",
        "note": "Fictional sample: service ticket requested"
    },
    {
        "timestamp": "2026-10-20T09:15:00",
        "event_id": 4769,
        "account": "svc_backup",
        "service": "MSSQLSvc/DB01.example.test",
        "ticket_encryption": "RC4",
        "source_host": "WS-014",
        "note": "Fictional sample: repeated service ticket request"
    },
    {
        "timestamp": "2026-10-20T09:16:00",
        "event_id": 4769,
        "account": "svc_reports",
        "service": "HTTP/APP01.example.test",
        "ticket_encryption": "AES256",
        "source_host": "WS-021",
        "note": "Fictional sample: service ticket requested"
    },
    {
        "timestamp": "2026-10-20T09:22:00",
        "event_id": 4624,
        "account": "analyst1",
        "service": "Interactive logon",
        "ticket_encryption": "N/A",
        "source_host": "WS-021",
        "note": "Fictional sample: successful logon"
    }
]

def flag_event(event):
    """Return simple review flags; flags are leads for investigation, not proof."""
    flags = []
    if event.get("event_id") == 4769 and event.get("ticket_encryption") == "RC4":
        flags.append("Review RC4-encrypted service ticket")
    if event.get("event_id") == 4769 and event.get("account", "").lower().startswith("svc_"):
        flags.append("Review service-account ticket request")
    return flags

def analyze_events(events):
    """Summarize events and attach review flags."""
    reviewed = []
    for event in events:
        item = dict(event)
        item["review_flags"] = flag_event(event)
        reviewed.append(item)
    event_counts = Counter(str(e.get("event_id", "unknown")) for e in events)
    flagged_count = sum(bool(e["review_flags"]) for e in reviewed)
    return {
        "total_events": len(events),
        "event_id_counts": dict(event_counts),
        "events_with_review_flags": flagged_count,
        "reviewed_events": reviewed,
    }

def hardening_checklist():
    """Return recommended defensive checks for a lab administrator."""
    return [
        {"control": "Inventory service accounts and their SPNs", "status": "Review required"},
        {"control": "Use long, unique, managed service-account credentials where supported", "status": "Review required"},
        {"control": "Prefer AES encryption and assess legacy RC4 dependencies", "status": "Review required"},
        {"control": "Apply least privilege to service accounts", "status": "Review required"},
        {"control": "Review and test GPO changes before broad deployment", "status": "Review required"},
        {"control": "Enable suitable auditing and monitor unusual service-ticket patterns", "status": "Review required"},
    ]

def main():
    report = analyze_events(SAMPLE_EVENTS)
    print("ACTIVE DIRECTORY DEFENSIVE LAB — SIMULATED RESULTS")
    print("=" * 54)
    print(f"Sample events analyzed: {report['total_events']}")
    print(f"Events with review flags: {report['events_with_review_flags']}")
    print("\nEvent ID counts:")
    for event_id, count in sorted(report["event_id_counts"].items()):
        print(f"  {event_id}: {count}")
    print("\nEvents needing analyst review:")
    for event in report["reviewed_events"]:
        if event["review_flags"]:
            print(f"- {event['timestamp']} | {event['account']} | {event['service']}")
            for flag in event["review_flags"]:
                print(f"    * {flag}")
    print("\nDefensive hardening checklist:")
    for item in hardening_checklist():
        print(f"- [ ] {item['control']} ({item['status']})")

    output_path = Path("simulated_analysis_report.json")
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nSaved simulated analysis to: {output_path.resolve()}")
    print("Reminder: these are fictional events; flags are not proof of an attack.")

if __name__ == "__main__":
    main()
