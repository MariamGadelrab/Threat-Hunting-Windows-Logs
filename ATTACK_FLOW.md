# Attack Flow Visualization

## Complete Attack Chain

```
┌─────────────────────────────────────────────────────────────────────┐
│                         ATTACK TIMELINE                              │
│                    March 4, 2024 (10:45 - 11:35 UTC)               │
└─────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│ PHASE 1: INITIAL ACCESS (10:45 UTC)                                 │
├──────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  External IP: 203.0.113.45                                           │
│         │                                                             │
│         │ VPN Connection                                             │
│         ▼                                                             │
│  ┌─────────────┐                                                     │
│  │   WKS-001   │  ◄── contractor_temp account                        │
│  └─────────────┘                                                     │
│                                                                       │
│  ✓ Event 4624: Successful logon (Type 10 - RemoteInteractive)       │
│  ✓ Event 4672: Special privileges assigned                          │
│  ⚠ MITRE ATT&CK: T1078 (Valid Accounts)                            │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│ PHASE 2: CREDENTIAL ACCESS (10:48 - 10:50 UTC)                      │
├──────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌─────────────┐                                                     │
│  │   WKS-001   │                                                     │
│  └──────┬──────┘                                                     │
│         │                                                             │
│         │ PowerShell -ExecutionPolicy Bypass                         │
│         ▼                                                             │
│  ┌─────────────────────────────────┐                                │
│  │  rundll32.exe comsvcs.dll       │                                │
│  │  MiniDump → LSASS Memory Dump   │                                │
│  └─────────────────────────────────┘                                │
│         │                                                             │
│         │ procdump.exe -ma lsass.exe                                 │
│         ▼                                                             │
│  ┌─────────────────────────────────┐                                │
│  │  lsass.dmp (Credentials Stolen) │                                │
│  └─────────────────────────────────┘                                │
│                                                                       │
│  ✓ Event 4656: Handle to LSASS requested                            │
│  ✓ Event 4663: LSASS memory accessed                                │
│  ✓ Event 4688: Suspicious process creation                          │
│  ⚠ MITRE ATT&CK: T1003.001 (LSASS Memory)                          │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│ PHASE 3: DISCOVERY (10:52 - 10:54 UTC)                              │
├──────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌─────────────┐                                                     │
│  │   WKS-001   │                                                     │
│  └──────┬──────┘                                                     │
│         │                                                             │
│         │ net user administrator /domain                             │
│         │ nltest.exe /dclist:                                        │
│         ▼                                                             │
│  ┌─────────────────────────────────┐                                │
│  │  Domain Topology Mapped         │                                │
│  │  - Admin accounts identified    │                                │
│  │  - Domain controllers located   │                                │
│  └─────────────────────────────────┘                                │
│                                                                       │
│  ✓ Event 4688: Reconnaissance commands                              │
│  ⚠ MITRE ATT&CK: T1087.002 (Domain Account Discovery)              │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│ PHASE 4: PRIVILEGE ESCALATION (10:56 - 10:58 UTC)                   │
├──────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌─────────────┐                                                     │
│  │   WKS-001   │                                                     │
│  └──────┬──────┘                                                     │
│         │                                                             │
│         │ runas.exe /user:admin cmd.exe                              │
│         │ (Using stolen credentials)                                 │
│         ▼                                                             │
│  ┌─────────────────────────────────┐                                │
│  │  Admin Account Compromised      │                                │
│  │  Full Domain Admin Rights       │                                │
│  └─────────────────────────────────┘                                │
│                                                                       │
│  ✓ Event 4648: Explicit credential usage                            │
│  ✓ Event 4624: Admin logon from external IP                         │
│  ✓ Event 4672: Admin privileges assigned                            │
│  ⚠ MITRE ATT&CK: T1078.002 (Domain Accounts)                       │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│ PHASE 5: LATERAL MOVEMENT (11:00 - 11:10 UTC)                       │
├──────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌─────────────┐      ┌─────────────┐      ┌─────────────┐         │
│  │   WKS-001   │─────▶│   WKS-002   │─────▶│   WKS-003   │         │
│  └─────────────┘      └─────────────┘      └─────────────┘         │
│   10.10.1.50          10.10.1.51           10.10.1.52              │
│        │                    │                     │                  │
│        │ Network Logon      │ Pass-the-Hash      │                  │
│        │ (Type 3)           │ (RC4 Kerberos)     │                  │
│        ▼                    ▼                     ▼                  │
│  ┌─────────────────────────────────────────────────────┐            │
│  │  Each Host:                                          │            │
│  │  • PowerShell execution                              │            │
│  │  • LSASS access                                      │            │
│  │  • SAM database export                               │            │
│  │  • Credential harvesting                             │            │
│  └─────────────────────────────────────────────────────┘            │
│                                                                       │
│  ✓ Event 4624: Network logons (Type 3)                              │
│  ✓ Event 4769: Kerberos tickets with RC4                            │
│  ✓ Event 4672: Privilege assignments                                │
│  ⚠ MITRE ATT&CK: T1021 (Remote Services)                           │
│  ⚠ MITRE ATT&CK: T1550.002 (Pass the Hash)                         │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│ PHASE 6: DOMAIN COMPROMISE (11:10 - 11:13 UTC)                      │
├──────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌─────────────┐                                                     │
│  │   WKS-003   │                                                     │
│  └──────┬──────┘                                                     │
│         │                                                             │
│         │ Network Logon (admin)                                      │
│         ▼                                                             │
│  ┌─────────────┐                                                     │
│  │    DC-01    │  ◄── DOMAIN CONTROLLER                             │
│  └──────┬──────┘                                                     │
│         │                                                             │
│         │ ntdsutil.exe "ac i ntds" ifm "create full c:\temp"        │
│         ▼                                                             │
│  ┌─────────────────────────────────┐                                │
│  │  NTDS.dit Extracted             │                                │
│  │  ⚠ ALL DOMAIN CREDENTIALS      │                                │
│  │  ⚠ COMPLETE DOMAIN COMPROMISE  │                                │
│  └─────────────────────────────────┘                                │
│                                                                       │
│  ✓ Event 4624: Admin logon to DC                                    │
│  ✓ Event 4688: ntdsutil.exe execution                               │
│  ✓ Event 4662: AD object operation                                  │
│  ⚠ MITRE ATT&CK: T1003.003 (NTDS)                                  │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│ PHASE 7: CLEANUP (11:35 UTC)                                        │
├──────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌─────────────┐                                                     │
│  │   WKS-001   │                                                     │
│  │   WKS-002   │  ◄── Logoff events                                 │
│  │   WKS-003   │                                                     │
│  └─────────────┘                                                     │
│                                                                       │
│  ✓ Event 4634: Logoff events                                        │
│  ⚠ Attacker maintains persistent access via stolen credentials      │
└──────────────────────────────────────────────────────────────────────┘
```

## Attack Statistics

| Metric | Value |
|--------|-------|
| **Total Duration** | 50 minutes |
| **Hosts Compromised** | 4 (WKS-001, WKS-002, WKS-003, DC-01) |
| **Accounts Compromised** | 2 (contractor_temp, admin) |
| **Techniques Used** | 10 MITRE ATT&CK techniques |
| **Credentials Stolen** | All domain users |
| **Detection Delay** | Post-incident (threat hunting) |

## MITRE ATT&CK Mapping

```
┌────────────────────────────────────────────────────────────────┐
│                    MITRE ATT&CK COVERAGE                        │
├────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Initial Access                                                 │
│  └─ T1078: Valid Accounts ✓                                    │
│                                                                 │
│  Execution                                                      │
│  ├─ T1059.001: PowerShell ✓                                    │
│  └─ T1047: Windows Management Instrumentation ✓                │
│                                                                 │
│  Privilege Escalation                                           │
│  └─ T1134: Access Token Manipulation ✓                         │
│                                                                 │
│  Credential Access                                              │
│  ├─ T1003.001: LSASS Memory ✓                                  │
│  ├─ T1003.002: Security Account Manager ✓                      │
│  └─ T1003.003: NTDS ✓                                          │
│                                                                 │
│  Discovery                                                      │
│  └─ T1087.002: Domain Account Discovery ✓                      │
│                                                                 │
│  Lateral Movement                                               │
│  ├─ T1021: Remote Services ✓                                   │
│  └─ T1550.002: Pass the Hash ✓                                 │
│                                                                 │
└────────────────────────────────────────────────────────────────┘
```

## Detection Points

```
┌─────────────────────────────────────────────────────────────────┐
│                    WHERE WE DETECTED THE ATTACK                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ✓ LSASS Memory Access (Events 4656, 4663)                      │
│  ✓ Credential Dumping Tools (procdump, comsvcs.dll)             │
│  ✓ Suspicious PowerShell Flags (-ExecutionPolicy Bypass)        │
│  ✓ Network Logons from Internal IPs (Event 4624 Type 3)         │
│  ✓ Pass-the-Hash Indicators (RC4 Kerberos tickets)              │
│  ✓ Explicit Credential Usage (Event 4648)                       │
│  ✓ Multiple Privilege Escalations (Event 4672)                  │
│  ✓ Reconnaissance Commands (net user, nltest)                   │
│  ✓ NTDS.dit Extraction (ntdsutil.exe)                           │
│  ✓ External IP Admin Access                                     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Impact Assessment

```
┌─────────────────────────────────────────────────────────────────┐
│                         IMPACT SUMMARY                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Confidentiality:  🔴 CRITICAL                                  │
│  └─ All domain credentials exposed                              │
│                                                                  │
│  Integrity:        🟡 HIGH                                      │
│  └─ Attacker has admin access to modify systems                 │
│                                                                  │
│  Availability:     🟡 HIGH                                      │
│  └─ Potential for ransomware or system destruction              │
│                                                                  │
│  Overall Risk:     🔴 CRITICAL                                  │
│  └─ Complete domain compromise                                  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Recommended Response

```
┌─────────────────────────────────────────────────────────────────┐
│                    IMMEDIATE ACTIONS REQUIRED                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. CONTAIN                                                      │
│     • Isolate all compromised systems                            │
│     • Disable contractor_temp account                            │
│     • Block external IP 203.0.113.45                             │
│                                                                  │
│  2. ERADICATE                                                    │
│     • Reset ALL administrative passwords                         │
│     • Revoke all Kerberos tickets                                │
│     • Force domain-wide password reset                           │
│                                                                  │
│  3. RECOVER                                                      │
│     • Rebuild compromised systems                                │
│     • Restore from clean backups                                 │
│     • Verify no persistence mechanisms                           │
│                                                                  │
│  4. IMPROVE                                                      │
│     • Implement MFA on all remote access                         │
│     • Deploy EDR to all endpoints                                │
│     • Enable enhanced logging                                    │
│     • Conduct security assessment                                │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

**This visualization demonstrates the complete attack chain from initial access to domain compromise, showing the progression of the threat and detection points throughout the investigation.**
