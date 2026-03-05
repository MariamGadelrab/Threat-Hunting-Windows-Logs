# Threat Hunting Investigation Report
## Detecting Lateral Movement and Credential Dumping in Windows Logs

**Investigation Date:** March 4, 2024  
**Analyst:** Senior SOC Analyst  
**Classification:** CONFIDENTIAL  
**Status:** ACTIVE THREAT DETECTED

---

## Executive Summary

This threat hunting investigation identified a sophisticated attack campaign involving credential dumping and lateral movement across the enterprise network. The investigation analyzed 51 Windows event logs spanning approximately 3.5 hours of activity.

**Key Findings:**
- **Critical Threat Confirmed:** Active adversary with administrative access
- **Attack Vector:** External VPN access via contractor account
- **Compromise Scope:** 4 endpoints including domain controller
- **Techniques Observed:** Credential dumping, lateral movement, privilege escalation
- **Attacker Persistence:** 45+ minutes of active operations

**Immediate Actions Required:**
1. Isolate compromised contractor account (contractor_temp)
2. Reset all administrative credentials
3. Investigate external IP: 203.0.113.45
4. Audit domain controller for persistence mechanisms
5. Review VPN access controls

---

## Hunting Hypothesis

**Initial Hypothesis:**  
"If an adversary has gained initial access to the network, they will attempt to dump credentials from LSASS memory and use those credentials to move laterally to high-value targets including the domain controller."

**Validation Status:** ✅ CONFIRMED

The hypothesis was validated through multiple detection hits across credential access and lateral movement tactics. The attack followed a predictable pattern consistent with post-exploitation frameworks.

---

## Methodology

### Data Sources
- Windows Security Event Logs (Event IDs: 4624, 4625, 4648, 4656, 4663, 4672, 4688, 4769)
- Log collection period: March 4, 2024 08:15 - 11:45 UTC
- Total events analyzed: 51
- Endpoints monitored: WKS-001, WKS-002, WKS-003, DC-01

### Hunting Techniques
1. **Signature-based Detection:** Known credential dumping tool patterns
2. **Behavioral Analysis:** Anomalous process execution chains
3. **Timeline Analysis:** Sequential logon patterns indicating lateral movement
4. **Privilege Escalation Tracking:** Event 4672 correlation
5. **Network Logon Analysis:** Remote authentication patterns

### Tools Used
- Custom Python threat hunting framework
- Pandas for log analysis
- Detection engine with MITRE ATT&CK mapping

---

## Key Findings

### Finding 1: Initial Compromise via External VPN Access
**Severity:** HIGH  
**Timestamp:** 2024-03-04 10:45:23 UTC

A contractor account (contractor_temp) authenticated via VPN from external IP 203.0.113.45. This account immediately received special privileges (Event 4672) and began suspicious activity.

**Evidence:**
- Event 4624: Successful logon from 203.0.113.45
- Logon Type: 10 (RemoteInteractive/VPN)
- Immediate privilege assignment suspicious for contractor account

**Assessment:** This represents the initial access vector. The contractor account may be compromised or represents a malicious insider.

---

### Finding 2: Credential Dumping Operations
**Severity:** CRITICAL  
**Timestamp:** 2024-03-04 10:48:45 - 10:50:23 UTC

Multiple credential dumping techniques were observed on WKS-001:

**Technique 1: LSASS Memory Dump via Rundll32**
```
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump
```
- MITRE ATT&CK: T1003.001 (LSASS Memory)
- This is a known technique to dump LSASS without triggering AV

**Technique 2: Procdump Tool Usage**
```
procdump.exe -ma lsass.exe lsass.dmp
```
- MITRE ATT&CK: T1003.001
- Direct LSASS memory dump using Sysinternals tool
- Events 4656, 4663: Handle requested and access granted to LSASS

**Impact:** Adversary likely obtained plaintext passwords and NTLM hashes for all logged-on users, including administrative accounts.

---

### Finding 3: Domain Reconnaissance
**Severity:** MEDIUM  
**Timestamp:** 2024-03-04 10:52:34 - 10:54:45 UTC

Post-credential-dump, the adversary performed domain enumeration:

**Commands Executed:**
```
net user administrator /domain
nltest.exe /dclist:
```

**Purpose:** 
- Identify domain administrators
- Locate domain controllers
- Map network topology

**MITRE ATT&CK:** T1087.002 (Domain Account Discovery)

---

### Finding 4: Privilege Escalation to Admin Account
**Severity:** CRITICAL  
**Timestamp:** 2024-03-04 10:56:12 - 10:58:22 UTC

The adversary used explicit credentials (Event 4648) to escalate to the admin account:

```
runas.exe /user:admin cmd.exe
```

**Evidence:**
- Event 4648: Explicit credential usage
- Event 4624: Admin logon from external IP 203.0.113.45
- Event 4672: Special privileges assigned to admin

**Assessment:** Credentials obtained from LSASS dump were successfully used to authenticate as domain administrator.

---

### Finding 5: Lateral Movement Campaign
**Severity:** CRITICAL  
**Timestamp:** 2024-03-04 11:00:15 - 11:10:45 UTC

Systematic lateral movement across the network using compromised admin credentials:

**Movement Chain:**
1. WKS-001 → WKS-002 (11:00:15)
2. WKS-002 → WKS-003 (11:07:23)
3. WKS-003 → DC-01 (11:10:45)

**Indicators:**
- Event 4624 Logon Type 3 (Network logon) on each target
- Event 4672 (Special privileges) immediately after each logon
- Source IPs match previous compromised hosts

**MITRE ATT&CK:** T1021 (Remote Services)

---

### Finding 6: Pass-the-Hash Authentication
**Severity:** CRITICAL  
**Timestamp:** 2024-03-04 11:03:34 UTC

Kerberos authentication using RC4 encryption detected:

**Evidence:**
- Event 4769: Kerberos service ticket request
- Encryption type: RC4 (legacy, indicates Pass-the-Hash)
- Modern Windows uses AES256 by default

**MITRE ATT&CK:** T1550.002 (Pass the Hash)

**Assessment:** Adversary used NTLM hashes directly without knowing plaintext passwords.

---

### Finding 7: Domain Controller Compromise
**Severity:** CRITICAL  
**Timestamp:** 2024-03-04 11:10:45 - 11:13:18 UTC

The adversary successfully accessed the domain controller (DC-01) and attempted to extract the Active Directory database:

**Commands Executed:**
```
ntdsutil.exe "ac i ntds" ifm "create full c:\temp" q q
```

**Impact:**
- NTDS.dit contains all domain user password hashes
- Complete domain compromise
- Adversary can create Golden Tickets for persistence

**MITRE ATT&CK:** T1003.003 (NTDS)

**Evidence:**
- Event 4688: ntdsutil.exe process creation
- Event 4662: Operation performed on AD object

---

### Finding 8: Suspicious PowerShell Execution
**Severity:** HIGH  
**Timestamp:** Multiple instances

PowerShell used with suspicious flags across multiple hosts:

**Examples:**
```
powershell.exe -ExecutionPolicy Bypass
powershell.exe -NoProfile -Command IEX
powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA
```

**Indicators:**
- Execution policy bypass
- Base64 encoded commands
- IEX (Invoke-Expression) for code execution

**MITRE ATT&CK:** T1059.001 (PowerShell)

---

### Finding 9: Remote Execution via WMIC
**Severity:** HIGH  
**Timestamp:** 2024-03-04 11:09:12 UTC

WMIC used for remote process execution:

```
wmic.exe process call create powershell.exe
```

**MITRE ATT&CK:** T1047 (Windows Management Instrumentation)

**Assessment:** Alternative lateral movement technique, likely for persistence or additional payload deployment.

---

## Attack Timeline

```
08:15 - 10:45  Normal business operations
10:45:23       [INITIAL ACCESS] Contractor VPN logon from 203.0.113.45
10:46:15       [PRIVILEGE ESC] Special privileges assigned
10:47:32       [EXECUTION] PowerShell with bypass policy
10:48:45       [CREDENTIAL DUMP] Rundll32 LSASS dump technique
10:49:45       [CREDENTIAL DUMP] Procdump LSASS memory dump
10:52:34       [DISCOVERY] Domain enumeration (net user)
10:54:45       [DISCOVERY] Domain controller enumeration (nltest)
10:56:12       [PRIVILEGE ESC] Explicit credential usage (runas)
10:57:34       [PRIVILEGE ESC] Admin account compromise
11:00:15       [LATERAL MOVEMENT] WKS-001 → WKS-002
11:03:34       [CREDENTIAL ACCESS] Pass-the-Hash (RC4 Kerberos)
11:04:18       [CREDENTIAL DUMP] SAM database export attempt
11:07:23       [LATERAL MOVEMENT] WKS-002 → WKS-003
11:08:34       [EXECUTION] Base64 encoded PowerShell
11:09:12       [EXECUTION] WMIC remote execution
11:10:45       [LATERAL MOVEMENT] WKS-003 → DC-01 (Domain Controller)
11:12:34       [CREDENTIAL DUMP] NTDS.dit extraction (Domain database)
11:35:45       [CLEANUP] Contractor account logoff
```

**Total Attack Duration:** ~50 minutes  
**Dwell Time:** Unknown (may have prior access)

---

## Indicators of Compromise (IOCs)

### Network Indicators
- **Attacker IP:** 203.0.113.45
- **Internal Pivot IPs:** 10.10.1.50, 10.10.1.51, 10.10.1.52

### Account Indicators
- **Compromised Accounts:**
  - contractor_temp (initial access)
  - admin (escalated privileges)

### Host Indicators
- **Compromised Hosts:**
  - WKS-001 (initial compromise)
  - WKS-002 (lateral movement)
  - WKS-003 (lateral movement)
  - DC-01 (domain controller - CRITICAL)

### Process Indicators
- rundll32.exe with comsvcs.dll MiniDump
- procdump.exe targeting lsass.exe
- ntdsutil.exe with NTDS extraction commands
- powershell.exe with -ExecutionPolicy Bypass, -enc, IEX
- wmic.exe with process call create

### File Indicators
- lsass.dmp (memory dump file)
- sam.save (SAM database export)
- NTDS.dit extraction to c:\temp

---

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Observed |
|--------|--------------|----------------|----------|
| Initial Access | T1078 | Valid Accounts | ✅ VPN access |
| Execution | T1059.001 | PowerShell | ✅ Multiple instances |
| Execution | T1047 | Windows Management Instrumentation | ✅ WMIC |
| Privilege Escalation | T1134 | Access Token Manipulation | ✅ Runas |
| Credential Access | T1003.001 | LSASS Memory | ✅ Procdump, Rundll32 |
| Credential Access | T1003.002 | Security Account Manager | ✅ SAM export |
| Credential Access | T1003.003 | NTDS | ✅ ntdsutil |
| Discovery | T1087.002 | Domain Account Discovery | ✅ net user |
| Lateral Movement | T1021 | Remote Services | ✅ Network logons |
| Lateral Movement | T1550.002 | Pass the Hash | ✅ RC4 Kerberos |

**ATT&CK Navigator Layer:** 9 techniques across 6 tactics

---

## Detection Opportunities

### Existing Detections (Successful)
1. ✅ LSASS memory access monitoring (Events 4656, 4663)
2. ✅ Credential dumping tool signatures
3. ✅ Suspicious PowerShell command-line flags
4. ✅ Lateral movement via network logons
5. ✅ Pass-the-Hash via RC4 Kerberos tickets

### Detection Gaps (Recommendations)
1. ❌ External VPN access from contractor accounts not alerted
2. ❌ No alert on ntdsutil.exe execution on domain controller
3. ❌ WMIC remote execution not monitored
4. ❌ Base64 encoded PowerShell not decoded/analyzed
5. ❌ No behavioral analytics on rapid host-to-host movement

### Recommended Detection Rules

**Rule 1: LSASS Access from Non-System Process**
```
Event 4656 OR 4663
TargetObject: lsass.exe
ProcessName: NOT (wininit.exe, services.exe, csrss.exe)
Severity: CRITICAL
```

**Rule 2: Credential Dumping Tool Execution**
```
Event 4688
CommandLine: (procdump, mimikatz, comsvcs.dll MiniDump, ntdsutil)
Severity: CRITICAL
```

**Rule 3: Suspicious PowerShell Flags**
```
Event 4688
ProcessName: powershell.exe
CommandLine: (-enc, -ExecutionPolicy Bypass, IEX, -NoProfile)
Severity: HIGH
```

**Rule 4: Lateral Movement - Admin Account**
```
Event 4624
LogonType: 3
AccountName: admin OR domain admin
SourceIP: Internal network
Frequency: > 3 hosts in 10 minutes
Severity: CRITICAL
```

**Rule 5: Pass-the-Hash Indicator**
```
Event 4769
EncryptionType: RC4
AccountName: admin OR privileged account
Severity: HIGH
```

---

## Security Recommendations

### Immediate Actions (0-24 hours)
1. **Isolate Compromised Systems**
   - Disconnect WKS-001, WKS-002, WKS-003, DC-01 from network
   - Preserve memory and disk for forensics

2. **Credential Reset**
   - Reset ALL domain administrator passwords
   - Reset contractor_temp account password
   - Force password reset for all users on compromised hosts

3. **Revoke Access**
   - Disable contractor_temp account
   - Revoke all active Kerberos tickets (TGTs)
   - Block external IP 203.0.113.45 at firewall

4. **Hunt for Persistence**
   - Check for scheduled tasks, services, registry run keys
   - Review domain admin group membership changes
   - Audit Golden Ticket indicators (Event 4769 with unusual lifetimes)

### Short-term Actions (1-7 days)
1. **Forensic Investigation**
   - Full disk imaging of all compromised hosts
   - Memory analysis for injected code
   - Network traffic analysis for C2 communications

2. **Enhanced Monitoring**
   - Deploy EDR to all endpoints
   - Enable PowerShell script block logging
   - Implement Sysmon for detailed process monitoring

3. **Access Control Review**
   - Audit all VPN accounts, especially contractors
   - Implement MFA for all remote access
   - Review and restrict admin account usage

### Long-term Actions (1-3 months)
1. **Architecture Improvements**
   - Implement tiered admin model (separate admin workstations)
   - Deploy Privileged Access Workstations (PAWs)
   - Segment network to limit lateral movement

2. **Detection Engineering**
   - Implement all recommended detection rules
   - Deploy UEBA for anomalous authentication patterns
   - Create playbooks for credential dumping response

3. **Security Hardening**
   - Enable Credential Guard on all Windows 10+ systems
   - Disable NTLM authentication where possible
   - Implement LSASS protection (RunAsPPL)
   - Deploy application whitelisting

4. **Training and Awareness**
   - Incident response tabletop exercises
   - SOC analyst training on credential theft techniques
   - User awareness training on phishing and social engineering

---

## Lessons Learned

### What Went Well
- Event logging captured sufficient detail for investigation
- Threat hunting methodology successfully identified attack chain
- Timeline reconstruction was possible from available logs

### What Could Be Improved
- No real-time alerting on critical events (LSASS access, credential dumping)
- Contractor account had excessive privileges
- No MFA on VPN access
- Domain controller not adequately protected
- Lateral movement not detected in real-time

### Process Improvements
1. Implement automated threat hunting queries (daily/weekly)
2. Create detection rules for all MITRE ATT&CK techniques in use
3. Establish baseline for normal admin account behavior
4. Improve log aggregation and correlation capabilities

---

## Conclusion

This investigation confirmed an active, sophisticated attack campaign targeting credential theft and lateral movement. The adversary demonstrated knowledge of common post-exploitation techniques and successfully compromised the domain controller.

**Risk Assessment:** CRITICAL - Full domain compromise achieved

**Recommended Classification:** Security Incident - Requires full incident response activation

**Next Steps:**
1. Activate incident response team
2. Execute containment procedures
3. Begin forensic investigation
4. Notify stakeholders per incident response plan

---

**Report Prepared By:** Senior SOC Analyst  
**Review Status:** Pending CISO Review  
**Distribution:** Incident Response Team, CISO, IT Security Leadership

**Appendix:**
- A: Full detection output (hunt_findings.csv)
- B: Attack timeline (timeline.csv)
- C: Threat summary statistics (threat_summary.csv)
