# Threat Hunting Investigation: Detecting Lateral Movement and Credential Dumping

A professional cybersecurity portfolio project demonstrating SOC analyst threat hunting techniques for detecting advanced persistent threats in Windows environments.

## Project Overview

This project simulates a real-world threat hunting engagement where a SOC analyst investigates suspicious activity in Windows event logs. The investigation uncovers a sophisticated attack campaign involving credential dumping, lateral movement, and domain controller compromise.

**Scenario:** An adversary gains initial access through a compromised contractor VPN account, dumps credentials from LSASS memory, and systematically moves laterally across the network to compromise the domain controller.

## Key Features

- Realistic Windows event log dataset (51 events across 4 hosts)
- Custom Python threat hunting framework
- Detection engine with MITRE ATT&CK mapping
- Automated analysis and reporting
- Professional investigation report
- Multiple output formats for different stakeholders

## Threat Hunting Methodology

### Hypothesis-Driven Hunting

The investigation follows a structured hypothesis:
> "If an adversary has gained initial access to the network, they will attempt to dump credentials from LSASS memory and use those credentials to move laterally to high-value targets including the domain controller."

### Detection Techniques

1. **Signature-Based Detection**
   - Known credential dumping tool patterns (mimikatz, procdump)
   - Suspicious command-line arguments
   - Malicious process names

2. **Behavioral Analysis**
   - Anomalous process execution chains
   - Unusual privilege escalations
   - Suspicious PowerShell usage

3. **Timeline Analysis**
   - Sequential logon patterns
   - Rapid host-to-host movement
   - Attack chain reconstruction

4. **Network Analysis**
   - Remote authentication patterns
   - External IP access
   - Lateral movement indicators

## Technologies Used

- **Python 3.x** - Core scripting language
- **Pandas** - Log analysis and data manipulation
- **Windows Event Logs** - Primary data source
- **MITRE ATT&CK Framework** - Threat classification

## Project Structure

```
threat-hunting-project/
├── data/
│   └── logs.csv                    # Windows event log dataset
├── src/
│   ├── hunt.py                     # Main threat hunting script
│   └── detection_engine.py         # Detection logic and rules
├── output/                         # Generated during execution
│   ├── hunt_findings.csv           # All detected threats
│   ├── credential_dumping_hits.csv # Credential theft indicators
│   ├── lateral_movement_hits.csv   # Lateral movement indicators
│   ├── timeline.csv                # Attack timeline
│   └── threat_summary.csv          # Executive summary statistics
├── report/
│   └── threat_hunt_report.md       # Professional investigation report
├── README.md                       # This file
└── PORTFOLIO.md                    # Skills demonstration summary
```

## Installation

### Prerequisites

- Python 3.7 or higher
- pip package manager

### Setup

1. Clone or download this project:
```bash
git clone <repository-url>
cd threat-hunting-project
```

2. Install required dependencies:
```bash
pip install pandas
```

No additional dependencies required - uses Python standard library.

## Usage

### Basic Execution

Run the threat hunting analysis with default settings:

```bash
python src/hunt.py
```

This will:
- Load logs from `data/logs.csv`
- Execute all detection rules
- Generate output files in `output/` directory
- Display summary to console

### Custom Input/Output

Specify custom input and output locations:

```bash
python src/hunt.py --input path/to/logs.csv --output path/to/results/
```

### Command-Line Options

```
--input   Path to input CSV file (default: data/logs.csv)
--output  Output directory for results (default: output/)
```

## Example Output

### Console Output

```
============================================================
THREAT HUNTING INVESTIGATION
Detecting Lateral Movement and Credential Dumping
============================================================
[+] Loading logs from data/logs.csv
[+] Loaded 51 log events
[+] Time range: 2024-03-04 08:15:23 to 2024-03-04 11:45:18
[+] Hosts: 4
[+] Users: 6

[+] Running threat hunting detections...
[*] Hunting for credential dumping indicators...
    [!] Found 8 credential dumping indicators
[*] Hunting for lateral movement...
    [!] Found 12 lateral movement indicators
[*] Hunting for privilege escalation...
    [!] Found 4 privilege escalation indicators
[*] Hunting for suspicious processes...
    [!] Found 9 suspicious process indicators
[*] Hunting for external access...
    [!] Found 2 external access indicators

============================================================
THREAT HUNT SUMMARY
============================================================
Total Findings: 35

Severity Breakdown:
  Critical: 18
  High: 12
  Medium: 5

Top Detections:
  Credential Dumping Tool: procdump: 1
  LSASS Memory Access: 2
  Lateral Movement - Network Logon: 3
  Pass-the-Hash Indicator: 1
  NTDS Database Extraction: 1

MITRE ATT&CK Techniques:
  T1003: 8
  T1021: 6
  T1078: 4
  T1059.001: 3
  T1550.002: 1
============================================================

[+] Threat hunt complete! Results saved to output
```

### Generated Files

1. **hunt_findings.csv** - Complete list of all detected threats with:
   - Timestamp
   - Host and user
   - Detection name
   - Severity level
   - MITRE ATT&CK technique
   - Description and evidence

2. **credential_dumping_hits.csv** - Filtered view of credential theft activities

3. **lateral_movement_hits.csv** - Filtered view of lateral movement activities

4. **timeline.csv** - Chronological attack timeline for incident response

5. **threat_summary.csv** - Executive summary with statistics

## Detection Coverage

### MITRE ATT&CK Techniques Detected

| Technique ID | Technique Name | Description |
|--------------|----------------|-------------|
| T1003.001 | LSASS Memory | Credential dumping from LSASS process |
| T1003.002 | Security Account Manager | SAM database extraction |
| T1003.003 | NTDS | Active Directory database extraction |
| T1021 | Remote Services | Lateral movement via network logons |
| T1047 | Windows Management Instrumentation | WMIC remote execution |
| T1059.001 | PowerShell | Malicious PowerShell usage |
| T1078 | Valid Accounts | Compromised account usage |
| T1087.002 | Domain Account Discovery | Domain enumeration |
| T1134 | Access Token Manipulation | Privilege escalation |
| T1550.002 | Pass the Hash | NTLM hash authentication |

### Windows Event IDs Analyzed

- **4624** - Successful logon (detects initial access and lateral movement)
- **4625** - Failed logon (detects brute force attempts)
- **4648** - Explicit credential use (detects credential theft usage)
- **4656** - Handle to object requested (detects LSASS access)
- **4663** - Access to object (detects LSASS memory access)
- **4672** - Special privileges assigned (detects privilege escalation)
- **4688** - Process creation (detects malicious tools and commands)
- **4769** - Kerberos service ticket (detects Pass-the-Hash)

## Dataset Details

### Simulated Environment

- **Hosts:** 4 endpoints (WKS-001, WKS-002, WKS-003, DC-01)
- **Users:** 6 accounts (john.smith, sarah.jones, mike.wilson, admin, contractor_temp, SYSTEM)
- **Time Range:** ~3.5 hours of activity
- **Total Events:** 51 log entries

### Attack Simulation

The dataset includes a realistic attack chain:

1. **Initial Access** (10:45 UTC) - Compromised contractor VPN account
2. **Credential Dumping** (10:48-10:50 UTC) - LSASS memory dump using multiple techniques
3. **Discovery** (10:52-10:54 UTC) - Domain and network enumeration
4. **Privilege Escalation** (10:56-10:58 UTC) - Escalation to admin account
5. **Lateral Movement** (11:00-11:10 UTC) - Movement across 3 workstations
6. **Domain Compromise** (11:10-11:13 UTC) - Domain controller access and NTDS extraction

### Benign Activity

The dataset includes normal business operations to simulate realistic noise:
- User logons and logoffs
- Standard application launches (Office, Chrome, Teams)
- System processes
- Normal Kerberos authentication

## Key Findings

The threat hunt identified:

- **35 total security findings**
- **18 critical severity alerts**
- **Complete domain compromise** via NTDS.dit extraction
- **Attack duration:** ~50 minutes
- **Compromised accounts:** 2 (contractor_temp, admin)
- **Compromised hosts:** 4 (including domain controller)

## Skills Demonstrated

This project showcases:

- **Threat Hunting** - Hypothesis-driven investigation methodology
- **Log Analysis** - Windows event log interpretation and correlation
- **Python Development** - Custom security tooling and automation
- **MITRE ATT&CK** - Threat classification and mapping
- **Incident Response** - Timeline reconstruction and IOC identification
- **Security Analysis** - Pattern recognition and anomaly detection
- **Technical Writing** - Professional security reporting
- **Detection Engineering** - Creating detection rules and logic

## Real-World Applications

This project demonstrates skills directly applicable to:

- SOC Analyst roles
- Threat Hunter positions
- Incident Response team members
- Security Engineer roles
- Detection Engineering positions
- Cybersecurity Analyst careers

## Future Enhancements

Potential improvements for this project:

- [ ] Machine learning for anomaly detection
- [ ] Integration with SIEM platforms (Splunk, ELK)
- [ ] Real-time log streaming and analysis
- [ ] Automated response actions
- [ ] Threat intelligence integration
- [ ] Graph-based attack path visualization
- [ ] Additional data sources (network logs, EDR telemetry)
- [ ] Web-based dashboard for findings

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Windows Security Event Log Encyclopedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
- [SANS Threat Hunting Resources](https://www.sans.org/cyber-security-courses/advanced-threat-hunting/)
- [Microsoft Security Auditing](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/security-auditing-overview)

## License

This project is created for educational and portfolio purposes.

## Author

Mariam Gadelrab
Cybersecurity / SOC Engineer 

## Contact

For questions or collaboration opportunities, please reach out via:
- LinkedIn: [Your Profile]
- Email: [Your Email]
- GitHub: [Your GitHub]

---

**Note:** This is a simulated threat hunting exercise. All data is synthetic and created for educational purposes. No real systems were compromised in the creation of this project.
