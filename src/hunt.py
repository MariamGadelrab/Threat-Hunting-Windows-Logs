"""
Threat Hunting Script - Main Entry Point
Analyzes Windows event logs to detect lateral movement and credential dumping
Author: SOC Analyst
"""

import pandas as pd
import argparse
import os
from datetime import datetime
from detection_engine import DetectionEngine


class ThreatHunter:
    """Main threat hunting orchestrator"""
    
    def __init__(self, input_file, output_dir):
        self.input_file = input_file
        self.output_dir = output_dir
        self.detection_engine = DetectionEngine()
        self.logs_df = None
        self.all_findings = []
        
    def load_logs(self):
        """Load Windows event logs from CSV"""
        print(f"[+] Loading logs from {self.input_file}")
        try:
            self.logs_df = pd.read_csv(self.input_file)
            print(f"[+] Loaded {len(self.logs_df)} log events")
            print(f"[+] Time range: {self.logs_df['timestamp_utc'].min()} to {self.logs_df['timestamp_utc'].max()}")
            print(f"[+] Hosts: {self.logs_df['host'].nunique()}")
            print(f"[+] Users: {self.logs_df['user'].nunique()}")
            return True
        except Exception as e:
            print(f"[-] Error loading logs: {e}")
            return False
    
    def run_detections(self):
        """Execute all threat hunting detections"""
        print("\n[+] Running threat hunting detections...")
        
        # Run credential dumping detection
        print("[*] Hunting for credential dumping indicators...")
        cred_dump_findings = self.detection_engine.detect_credential_dumping(self.logs_df)
        if not cred_dump_findings.empty:
            print(f"    [!] Found {len(cred_dump_findings)} credential dumping indicators")
            self.all_findings.append(cred_dump_findings)
        
        # Run lateral movement detection
        print("[*] Hunting for lateral movement...")
        lateral_findings = self.detection_engine.detect_lateral_movement(self.logs_df)
        if not lateral_findings.empty:
            print(f"    [!] Found {len(lateral_findings)} lateral movement indicators")
            self.all_findings.append(lateral_findings)
        
        # Run privilege escalation detection
        print("[*] Hunting for privilege escalation...")
        priv_esc_findings = self.detection_engine.detect_privilege_escalation(self.logs_df)
        if not priv_esc_findings.empty:
            print(f"    [!] Found {len(priv_esc_findings)} privilege escalation indicators")
            self.all_findings.append(priv_esc_findings)
        
        # Run suspicious process detection
        print("[*] Hunting for suspicious processes...")
        process_findings = self.detection_engine.detect_suspicious_processes(self.logs_df)
        if not process_findings.empty:
            print(f"    [!] Found {len(process_findings)} suspicious process indicators")
            self.all_findings.append(process_findings)
        
        # Run external access detection
        print("[*] Hunting for external access...")
        external_findings = self.detection_engine.detect_external_access(self.logs_df)
        if not external_findings.empty:
            print(f"    [!] Found {len(external_findings)} external access indicators")
            self.all_findings.append(external_findings)
        
        return True
    
    def generate_outputs(self):
        """Generate all output files"""
        print(f"\n[+] Generating output files in {self.output_dir}")
        
        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)
        
        if not self.all_findings:
            print("[-] No findings to report")
            return False
        
        # Combine all findings
        combined_findings = pd.concat(self.all_findings, ignore_index=True)
        combined_findings = combined_findings.sort_values('timestamp')
        
        # Save main findings file
        findings_file = os.path.join(self.output_dir, 'hunt_findings.csv')
        combined_findings.to_csv(findings_file, index=False)
        print(f"[+] Saved: {findings_file}")
        
        # Save credential dumping specific findings
        cred_dump_file = os.path.join(self.output_dir, 'credential_dumping_hits.csv')
        cred_dump_hits = combined_findings[
            combined_findings['detection'].str.contains('Credential|LSASS|SAM|NTDS', case=False, na=False)
        ]
        if not cred_dump_hits.empty:
            cred_dump_hits.to_csv(cred_dump_file, index=False)
            print(f"[+] Saved: {cred_dump_file}")
        
        # Save lateral movement specific findings
        lateral_file = os.path.join(self.output_dir, 'lateral_movement_hits.csv')
        lateral_hits = combined_findings[
            combined_findings['detection'].str.contains('Lateral|Pass-the-Hash', case=False, na=False)
        ]
        if not lateral_hits.empty:
            lateral_hits.to_csv(lateral_file, index=False)
            print(f"[+] Saved: {lateral_file}")
        
        # Generate timeline
        timeline_file = os.path.join(self.output_dir, 'timeline.csv')
        timeline = combined_findings[['timestamp', 'host', 'user', 'detection', 'severity']].copy()
        timeline = timeline.sort_values('timestamp')
        timeline.to_csv(timeline_file, index=False)
        print(f"[+] Saved: {timeline_file}")
        
        # Generate threat summary
        self.generate_threat_summary(combined_findings)
        
        return True
    
    def generate_threat_summary(self, findings):
        """Generate executive threat summary"""
        summary_file = os.path.join(self.output_dir, 'threat_summary.csv')
        
        # Count by severity
        severity_counts = findings['severity'].value_counts().to_dict()
        
        # Count by MITRE technique
        technique_counts = findings['mitre_technique'].value_counts().to_dict()
        
        # Count by detection type
        detection_counts = findings['detection'].value_counts().to_dict()
        
        # Affected hosts
        affected_hosts = findings['host'].nunique() if 'host' in findings.columns else 0
        
        # Affected users
        affected_users = findings['user'].nunique() if 'user' in findings.columns else 0
        
        # Create summary dataframe
        summary_data = []
        
        summary_data.append({
            'metric': 'Total Findings',
            'value': len(findings),
            'category': 'Overview'
        })
        
        summary_data.append({
            'metric': 'Affected Hosts',
            'value': affected_hosts,
            'category': 'Overview'
        })
        
        summary_data.append({
            'metric': 'Affected Users',
            'value': affected_users,
            'category': 'Overview'
        })
        
        for severity, count in severity_counts.items():
            summary_data.append({
                'metric': f'{severity} Severity',
                'value': count,
                'category': 'Severity'
            })
        
        for technique, count in technique_counts.items():
            summary_data.append({
                'metric': technique,
                'value': count,
                'category': 'MITRE ATT&CK'
            })
        
        summary_df = pd.DataFrame(summary_data)
        summary_df.to_csv(summary_file, index=False)
        print(f"[+] Saved: {summary_file}")
    
    def print_summary(self):
        """Print hunt summary to console"""
        if not self.all_findings:
            print("\n[+] Hunt complete - No threats detected")
            return
        
        combined_findings = pd.concat(self.all_findings, ignore_index=True)
        
        print("\n" + "="*60)
        print("THREAT HUNT SUMMARY")
        print("="*60)
        print(f"Total Findings: {len(combined_findings)}")
        print(f"\nSeverity Breakdown:")
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            count = len(combined_findings[combined_findings['severity'] == severity])
            if count > 0:
                print(f"  {severity}: {count}")
        
        print(f"\nTop Detections:")
        top_detections = combined_findings['detection'].value_counts().head(5)
        for detection, count in top_detections.items():
            print(f"  {detection}: {count}")
        
        print(f"\nMITRE ATT&CK Techniques:")
        techniques = combined_findings['mitre_technique'].value_counts()
        for technique, count in techniques.items():
            print(f"  {technique}: {count}")
        
        print("="*60)
    
    def run(self):
        """Execute complete threat hunt"""
        print("="*60)
        print("THREAT HUNTING INVESTIGATION")
        print("Detecting Lateral Movement and Credential Dumping")
        print("="*60)
        
        # Load logs
        if not self.load_logs():
            return False
        
        # Run detections
        if not self.run_detections():
            return False
        
        # Generate outputs
        if not self.generate_outputs():
            return False
        
        # Print summary
        self.print_summary()
        
        print(f"\n[+] Threat hunt complete! Results saved to {self.output_dir}")
        return True


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Threat Hunting Tool - Detect lateral movement and credential dumping'
    )
    parser.add_argument(
        '--input',
        default='data/logs.csv',
        help='Input CSV file containing Windows event logs'
    )
    parser.add_argument(
        '--output',
        default='output',
        help='Output directory for hunt results'
    )
    
    args = parser.parse_args()
    
    # Create and run threat hunter
    hunter = ThreatHunter(args.input, args.output)
    success = hunter.run()
    
    return 0 if success else 1


if __name__ == '__main__':
    exit(main())
