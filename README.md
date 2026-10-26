# Active Directory Defensive Lab (Simulation)

**Project:** Active Directory Attack Lab: Kerberos service-ticket review and GPO hardening recommendations  
**Program:** IBM SkillsBuild Cyber Security 2026  
**Author:** Paru (replace with your full name if required)

## Overview
This beginner-friendly Python project analyzes a small set of fictional Windows security events and flags service-ticket events for analyst review. It also provides a defensive hardening checklist related to service accounts, Kerberos encryption, least privilege, auditing, and safe Group Policy change management.

## Important scope statement
This submission is a **simulation** using fictional sample data. It does not connect to a real Windows domain, perform Kerberoasting, collect real logs, or modify Group Policy. The flags are simple review indicators, not proof of an attack.

## Technologies
- Python 3
- Jupyter Notebook (optional, for the `.ipynb` file)
- Python standard library: `collections`, `json`, and `pathlib`

## Files
- `Paru_Active_Directory_Defensive_Lab.ipynb` — notebook version of the code
- `Paru_Active_Directory_Defensive_Lab.py` — script version of the code
- `requirements.txt` — dependencies (none outside the Python standard library)
- `Paru_Active_Directory_Project_Report.docx` — project report

## Run instructions
### Run the Python script
1. Install Python 3 if it is not already installed.
2. Open a terminal in the folder containing the files.
3. Run: `python Paru_Active_Directory_Defensive_Lab.py`
4. The script prints a summary and creates `simulated_analysis_report.json` in the current directory.

### Run the notebook
1. Open the `.ipynb` file in Jupyter Notebook or JupyterLab.
2. Run each cell from top to bottom.
3. The last cell writes `simulated_analysis_report.json`.

No third-party Python packages are required.

## Sample data
The fictional sample events are embedded in the code so the project can run offline. They are not real user or organization logs.

## Defensive recommendations
- Inventory service accounts and their Service Principal Names (SPNs).
- Use managed service accounts and long, unique credentials where supported.
- Review legacy RC4 usage and plan safe migration to stronger supported encryption.
- Apply least privilege to service accounts.
- Enable appropriate auditing and investigate unusual ticket-request patterns.
- Test Group Policy changes before broad deployment and maintain a rollback plan.

## Limitations and future work
The current rules are intentionally simple and may produce false positives. A future version could parse sanitized exported event logs, add unit tests, and provide a richer dashboard. Any real-world testing should be performed only in an authorized isolated lab.

## Dataset link
No external dataset is used. The sample data is synthetic and embedded in the source code.
