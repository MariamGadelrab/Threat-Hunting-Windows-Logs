# Quick Start Guide

## 5-Minute Setup and Execution

### Step 1: Install Python
Ensure Python 3.7+ is installed:
```bash
python --version
```

### Step 2: Install Dependencies
```bash
pip install pandas
```

### Step 3: Run the Threat Hunt
```bash
python src/hunt.py
```

That's it! Results will be in the `output/` directory.

## What You'll Get

After running the script, you'll have:

1. **Console Output** - Summary of findings with severity breakdown
2. **hunt_findings.csv** - All 29 detected threats
3. **credential_dumping_hits.csv** - 8 credential theft indicators
4. **lateral_movement_hits.csv** - 9 lateral movement detections
5. **timeline.csv** - Chronological attack timeline
6. **threat_summary.csv** - Executive statistics

## Key Findings Preview

The analysis will detect:
- ✅ 13 Critical severity threats
- ✅ 12 High severity threats
- ✅ 4 Medium severity threats
- ✅ 10 MITRE ATT&CK techniques
- ✅ Complete attack chain from initial access to domain compromise

## Understanding the Results

### Critical Findings
- Credential dumping using procdump and comsvcs.dll
- NTDS.dit extraction from domain controller
- Pass-the-Hash authentication
- Admin account lateral movement chain

### Attack Timeline
```
10:45 → Initial VPN access (contractor_temp)
10:48 → LSASS credential dumping
10:56 → Privilege escalation to admin
11:00 → Lateral movement begins
11:10 → Domain controller compromised
11:12 → NTDS database extracted
```

## Next Steps

1. Review `output/hunt_findings.csv` for detailed detections
2. Read `report/threat_hunt_report.md` for full investigation
3. Check `PORTFOLIO.md` for skills demonstrated
4. Customize detection rules in `src/detection_engine.py`

## Customization

### Use Your Own Logs
```bash
python src/hunt.py --input your_logs.csv --output your_results/
```

### Required CSV Format
Your log file must have these columns:
- timestamp_utc
- host
- user
- event_id
- log_channel
- source_ip
- process_name
- command_line
- outcome
- details

## Troubleshooting

**Issue:** ModuleNotFoundError: No module named 'pandas'  
**Solution:** Run `pip install pandas`

**Issue:** FileNotFoundError: data/logs.csv  
**Solution:** Ensure you're running from the project root directory

**Issue:** No output files generated  
**Solution:** Check that the output directory is writable

## Demo Mode

Want to see it in action immediately? Just run:
```bash
python src/hunt.py
```

The included sample dataset (`data/logs.csv`) contains a complete simulated attack for demonstration purposes.

## Questions?

Check the full README.md for detailed documentation.
