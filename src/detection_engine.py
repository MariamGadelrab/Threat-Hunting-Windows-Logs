"""
Detection Engine for Threat Hunting
Contains detection logic for identifying suspicious patterns in Windows logs
"""

import pandas as pd
import re
from datetime import datetime


class DetectionEngine:
    """Core detection engine for threat hunting operations"""
    
    def __init__(self):
        self.detections = []
        self.severity_scores = {
            'Low': 1,
            'Medium': 2,
            'High': 3,
            'Critical': 4
        }
    
    def detect_credential_dumping(self, df):
        """
        Detect credential dumping indicators
        MITRE ATT&CK: T1003 - OS Credential Dumping
        """
        findings = []
        
        # Detection 1: LSASS memory access
        lsass_access = df[
            (df['process_name'].str.contains('lsass', case=False, na=False)) &
            (df['event_id'].isin([4656, 4663]))
        ]
        
        for idx, row in lsass_access.iterrows():
            findings.append({
                'timestamp': row['timestamp_utc'],
                'host': row['host'],
                'user': row['user'],
                'detection': 'LSASS Memory Access',
                'severity': 'High',
                'mitre_technique': 'T1003.001',
                'description': 'Suspicious access to LSASS process memory',
                'evidence': f"Event {row['event_id']} - {row['details']}"
            })
        
        # Detection 2: Credential dumping tools
        dump_tools = ['procdump', 'mimikatz', 'comsvcs.dll', 'MiniDump']
        for tool in dump_tools:
            tool_usage = df[
                df['command_line'].str.contains(tool, case=False, na=False) |
                df['process_name'].str.contains(tool, case=False, na=False)
            ]
            
            for idx, row in tool_usage.iterrows():
                findings.append({
                    'timestamp': row['timestamp_utc'],
                    'host': row['host'],
                    'user': row['user'],
                    'detection': f'Credential Dumping Tool: {tool}',
                    'severity': 'Critical',
                    'mitre_technique': 'T1003',
                    'description': f'Known credential dumping tool detected: {tool}',
                    'evidence': f"Command: {row['command_line']}"
                })
        
        # Detection 3: SAM database access
        sam_access = df[
            df['command_line'].str.contains('SAM|SECURITY|SYSTEM', case=False, na=False, regex=True) &
            df['command_line'].str.contains('reg.*save|copy', case=False, na=False, regex=True)
        ]
        
        for idx, row in sam_access.iterrows():
            findings.append({
                'timestamp': row['timestamp_utc'],
                'host': row['host'],
                'user': row['user'],
                'detection': 'SAM Database Export',
                'severity': 'Critical',
                'mitre_technique': 'T1003.002',
                'description': 'Attempt to export SAM database',
                'evidence': f"Command: {row['command_line']}"
            })
        
        # Detection 4: NTDS.dit extraction
        ntds_access = df[
            df['command_line'].str.contains('ntdsutil|ntds.dit', case=False, na=False, regex=True)
        ]
        
        for idx, row in ntds_access.iterrows():
            findings.append({
                'timestamp': row['timestamp_utc'],
                'host': row['host'],
                'user': row['user'],
                'detection': 'NTDS Database Extraction',
                'severity': 'Critical',
                'mitre_technique': 'T1003.003',
                'description': 'Active Directory database extraction attempt',
                'evidence': f"Command: {row['command_line']}"
            })
        
        return pd.DataFrame(findings)
    
    def detect_lateral_movement(self, df):
        """
        Detect lateral movement patterns
        MITRE ATT&CK: T1021 - Remote Services
        """
        findings = []
        
        # Detection 1: Remote logons (Type 3)
        remote_logons = df[
            (df['event_id'] == 4624) &
            (df['details'].str.contains('Logon Type 3', case=False, na=False))
        ]
        
        for idx, row in remote_logons.iterrows():
            # Check if source IP is internal (lateral movement indicator)
            if pd.notna(row['source_ip']) and row['source_ip'].startswith('10.10.1'):
                findings.append({
                    'timestamp': row['timestamp_utc'],
                    'source_host': row['source_ip'],
                    'target_host': row['host'],
                    'user': row['user'],
                    'detection': 'Lateral Movement - Network Logon',
                    'severity': 'High',
                    'mitre_technique': 'T1021',
                    'description': 'Remote network logon from internal host',
                    'evidence': f"User {row['user']} logged on to {row['host']} from {row['source_ip']}"
                })
        
        # Detection 2: Pass-the-Hash indicators (RC4 Kerberos tickets)
        pth_indicators = df[
            (df['event_id'] == 4769) &
            (df['details'].str.contains('RC4', case=False, na=False))
        ]
        
        for idx, row in pth_indicators.iterrows():
            findings.append({
                'timestamp': row['timestamp_utc'],
                'source_host': row['source_ip'],
                'target_host': row['host'],
                'user': row['user'],
                'detection': 'Pass-the-Hash Indicator',
                'severity': 'Critical',
                'mitre_technique': 'T1550.002',
                'description': 'Kerberos ticket with RC4 encryption (PtH indicator)',
                'evidence': f"Event 4769 - RC4 encryption used by {row['user']}"
            })
        
        # Detection 3: Explicit credential usage (Event 4648)
        explicit_creds = df[df['event_id'] == 4648]
        
        for idx, row in explicit_creds.iterrows():
            findings.append({
                'timestamp': row['timestamp_utc'],
                'source_host': row['source_ip'],
                'target_host': row['host'],
                'user': row['user'],
                'detection': 'Explicit Credential Usage',
                'severity': 'Medium',
                'mitre_technique': 'T1078',
                'description': 'User explicitly provided credentials (runas)',
                'evidence': f"Command: {row['command_line']}"
            })
        
        # Detection 4: Admin logon chain analysis
        admin_logons = df[
            (df['event_id'] == 4624) &
            (df['user'] == 'admin')
        ].sort_values('timestamp_utc')
        
        if len(admin_logons) > 2:
            hosts = admin_logons['host'].tolist()
            for i in range(len(hosts) - 1):
                findings.append({
                    'timestamp': admin_logons.iloc[i+1]['timestamp_utc'],
                    'source_host': hosts[i],
                    'target_host': hosts[i+1],
                    'user': 'admin',
                    'detection': 'Admin Account Lateral Movement Chain',
                    'severity': 'Critical',
                    'mitre_technique': 'T1078.002',
                    'description': f'Admin account moving from {hosts[i]} to {hosts[i+1]}',
                    'evidence': 'Sequential admin logons across multiple hosts'
                })
        
        return pd.DataFrame(findings)
    
    def detect_privilege_escalation(self, df):
        """
        Detect privilege escalation attempts
        MITRE ATT&CK: T1068, T1134
        """
        findings = []
        
        # Detection 1: Multiple privilege assignments
        priv_events = df[df['event_id'] == 4672]
        
        # Group by user and count
        priv_counts = priv_events.groupby('user').size()
        
        for user, count in priv_counts.items():
            if count > 2:  # Multiple privilege escalations
                user_events = priv_events[priv_events['user'] == user]
                findings.append({
                    'timestamp': user_events.iloc[-1]['timestamp_utc'],
                    'host': 'Multiple',
                    'user': user,
                    'detection': 'Multiple Privilege Escalations',
                    'severity': 'High',
                    'mitre_technique': 'T1134',
                    'description': f'User {user} received special privileges {count} times',
                    'evidence': f'Event 4672 occurred {count} times for this user'
                })
        
        # Detection 2: Suspicious privilege assignment from external IP
        external_priv = df[
            (df['event_id'] == 4672) &
            (df['source_ip'].notna()) &
            (~df['source_ip'].str.startswith('10.10.1', na=False))
        ]
        
        for idx, row in external_priv.iterrows():
            findings.append({
                'timestamp': row['timestamp_utc'],
                'host': row['host'],
                'user': row['user'],
                'detection': 'Privilege Escalation from External Source',
                'severity': 'Critical',
                'mitre_technique': 'T1078',
                'description': f'Special privileges assigned from external IP: {row["source_ip"]}',
                'evidence': f'Event 4672 from {row["source_ip"]}'
            })
        
        return pd.DataFrame(findings)
    
    def detect_suspicious_processes(self, df):
        """
        Detect suspicious process execution patterns
        """
        findings = []
        
        # Detection 1: PowerShell with suspicious flags
        suspicious_ps = df[
            (df['process_name'].str.contains('powershell', case=False, na=False)) &
            (df['command_line'].str.contains(
                'ExecutionPolicy Bypass|-enc|-NoProfile|IEX|Invoke-Expression',
                case=False, na=False, regex=True
            ))
        ]
        
        for idx, row in suspicious_ps.iterrows():
            findings.append({
                'timestamp': row['timestamp_utc'],
                'host': row['host'],
                'user': row['user'],
                'detection': 'Suspicious PowerShell Execution',
                'severity': 'High',
                'mitre_technique': 'T1059.001',
                'description': 'PowerShell with suspicious command-line flags',
                'evidence': f"Command: {row['command_line']}"
            })
        
        # Detection 2: Reconnaissance commands
        recon_commands = ['net user', 'net group', 'nltest', 'whoami', 'ipconfig /all']
        for cmd in recon_commands:
            recon_usage = df[
                df['command_line'].str.contains(cmd, case=False, na=False)
            ]
            
            for idx, row in recon_usage.iterrows():
                findings.append({
                    'timestamp': row['timestamp_utc'],
                    'host': row['host'],
                    'user': row['user'],
                    'detection': 'Reconnaissance Command',
                    'severity': 'Medium',
                    'mitre_technique': 'T1087',
                    'description': f'Reconnaissance command executed: {cmd}',
                    'evidence': f"Command: {row['command_line']}"
                })
        
        # Detection 3: WMIC remote execution
        wmic_exec = df[
            df['command_line'].str.contains('wmic.*process call create', case=False, na=False, regex=True)
        ]
        
        for idx, row in wmic_exec.iterrows():
            findings.append({
                'timestamp': row['timestamp_utc'],
                'host': row['host'],
                'user': row['user'],
                'detection': 'WMIC Remote Execution',
                'severity': 'High',
                'mitre_technique': 'T1047',
                'description': 'WMIC used for remote process execution',
                'evidence': f"Command: {row['command_line']}"
            })
        
        return pd.DataFrame(findings)
    
    def detect_external_access(self, df):
        """
        Detect suspicious external access patterns
        """
        findings = []
        
        # Detection: Logons from external IPs
        external_logons = df[
            (df['event_id'] == 4624) &
            (df['source_ip'].notna()) &
            (~df['source_ip'].str.startswith('10.10.1', na=False))
        ]
        
        for idx, row in external_logons.iterrows():
            severity = 'Critical' if row['user'] == 'admin' else 'High'
            findings.append({
                'timestamp': row['timestamp_utc'],
                'host': row['host'],
                'user': row['user'],
                'detection': 'External IP Logon',
                'severity': severity,
                'mitre_technique': 'T1078',
                'description': f'Logon from external IP: {row["source_ip"]}',
                'evidence': f'Event 4624 from {row["source_ip"]}'
            })
        
        return pd.DataFrame(findings)
