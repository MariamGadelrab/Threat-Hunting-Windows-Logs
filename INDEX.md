# Project Index - Threat Hunting Investigation

## 📋 Quick Navigation

### 🚀 Getting Started
- **[QUICK_START.md](QUICK_START.md)** - 5-minute setup and execution guide
- **[README.md](README.md)** - Complete project documentation
- **[requirements.txt](requirements.txt)** - Python dependencies

### 📊 Project Overview
- **[PROJECT_SUMMARY.md](PROJECT_SUMMARY.md)** - High-level project overview with statistics
- **[PORTFOLIO.md](PORTFOLIO.md)** - Skills and competencies demonstrated
- **[ATTACK_FLOW.md](ATTACK_FLOW.md)** - Visual attack chain diagram

### 📈 Executive Materials
- **[EXECUTIVE_BRIEF.md](EXECUTIVE_BRIEF.md)** - Executive summary for leadership
- **[report/threat_hunt_report.md](report/threat_hunt_report.md)** - Full 15-page investigation report

### 💻 Source Code
- **[src/hunt.py](src/hunt.py)** - Main threat hunting script (200+ lines)
- **[src/detection_engine.py](src/detection_engine.py)** - Detection logic library (300+ lines)

### 📁 Data Files
- **[data/logs.csv](data/logs.csv)** - 51 realistic Windows event logs

### 📤 Output Files (Generated)
- **[output/hunt_findings.csv](output/hunt_findings.csv)** - All 29 detected threats
- **[output/credential_dumping_hits.csv](output/credential_dumping_hits.csv)** - 8 credential theft indicators
- **[output/lateral_movement_hits.csv](output/lateral_movement_hits.csv)** - 9 lateral movement detections
- **[output/timeline.csv](output/timeline.csv)** - Chronological attack timeline
- **[output/threat_summary.csv](output/threat_summary.csv)** - Executive statistics

---

## 📖 Reading Guide by Audience

### For Hiring Managers
1. Start with **[PROJECT_SUMMARY.md](PROJECT_SUMMARY.md)** for quick overview
2. Review **[PORTFOLIO.md](PORTFOLIO.md)** for skills demonstrated
3. Check **[output/hunt_findings.csv](output/hunt_findings.csv)** for sample results
4. Skim **[src/hunt.py](src/hunt.py)** for code quality

**Time Required:** 10-15 minutes

### For Technical Reviewers
1. Read **[README.md](README.md)** for technical details
2. Review **[src/detection_engine.py](src/detection_engine.py)** for detection logic
3. Examine **[data/logs.csv](data/logs.csv)** for dataset quality
4. Check **[report/threat_hunt_report.md](report/threat_hunt_report.md)** for analysis depth

**Time Required:** 30-45 minutes

### For Security Professionals
1. Start with **[ATTACK_FLOW.md](ATTACK_FLOW.md)** for attack visualization
2. Read **[report/threat_hunt_report.md](report/threat_hunt_report.md)** for full investigation
3. Review **[src/detection_engine.py](src/detection_engine.py)** for detection techniques
4. Analyze **[output/hunt_findings.csv](output/hunt_findings.csv)** for detection coverage

**Time Required:** 45-60 minutes

### For Executives
1. Read **[EXECUTIVE_BRIEF.md](EXECUTIVE_BRIEF.md)** for business impact
2. Review **[PROJECT_SUMMARY.md](PROJECT_SUMMARY.md)** for project overview
3. Check **[output/threat_summary.csv](output/threat_summary.csv)** for key metrics

**Time Required:** 5-10 minutes

### For Students/Learners
1. Start with **[QUICK_START.md](QUICK_START.md)** to run the project
2. Read **[README.md](README.md)** for methodology
3. Study **[ATTACK_FLOW.md](ATTACK_FLOW.md)** to understand the attack
4. Review **[src/detection_engine.py](src/detection_engine.py)** to learn detection techniques
5. Read **[report/threat_hunt_report.md](report/threat_hunt_report.md)** for professional reporting

**Time Required:** 2-3 hours

---

## 🎯 Use Cases

### Portfolio Presentation
**Files to showcase:**
- PROJECT_SUMMARY.md (overview)
- PORTFOLIO.md (skills)
- output/hunt_findings.csv (results)
- src/hunt.py (code sample)

### Job Interview
**Files to discuss:**
- ATTACK_FLOW.md (technical knowledge)
- report/threat_hunt_report.md (analysis skills)
- src/detection_engine.py (coding ability)
- PORTFOLIO.md (competencies)

### Security Training
**Files to use:**
- ATTACK_FLOW.md (attack techniques)
- data/logs.csv (sample data)
- report/threat_hunt_report.md (investigation process)
- README.md (methodology)

### Detection Engineering
**Files to reference:**
- src/detection_engine.py (detection rules)
- output/hunt_findings.csv (detection results)
- report/threat_hunt_report.md (detection opportunities)

---

## 📊 Project Statistics

| Category | Count |
|----------|-------|
| **Documentation Files** | 8 |
| **Source Code Files** | 2 |
| **Data Files** | 1 |
| **Output Files** | 5 |
| **Total Lines of Code** | 500+ |
| **Total Documentation** | 10,000+ words |
| **MITRE Techniques** | 10 |
| **Detections** | 29 |

---

## 🔍 File Descriptions

### Documentation

**README.md** (Primary Documentation)
- Complete project overview
- Installation instructions
- Usage examples
- Detection coverage
- Skills demonstrated

**QUICK_START.md** (Quick Reference)
- 5-minute setup guide
- Basic usage
- Sample output
- Troubleshooting

**PROJECT_SUMMARY.md** (Overview)
- High-level statistics
- Key achievements
- Visual summaries
- Target audience guide

**PORTFOLIO.md** (Skills Showcase)
- Detailed skills breakdown
- Quantifiable achievements
- Real-world applications
- Learning outcomes

**ATTACK_FLOW.md** (Visual Guide)
- Attack chain visualization
- Phase-by-phase breakdown
- MITRE ATT&CK mapping
- Detection points

**EXECUTIVE_BRIEF.md** (Leadership Summary)
- Business impact assessment
- Risk analysis
- Financial estimates
- Recommendations

**report/threat_hunt_report.md** (Full Report)
- 15-page investigation report
- Executive summary
- Technical findings
- IOCs and recommendations

### Source Code

**src/hunt.py** (Main Script)
- Threat hunting orchestration
- Log loading and processing
- Output generation
- CLI interface

**src/detection_engine.py** (Detection Library)
- Detection rule implementations
- MITRE ATT&CK mapping
- Severity classification
- Evidence collection

### Data

**data/logs.csv** (Sample Dataset)
- 51 Windows event logs
- 4 hosts, 6 users
- Realistic attack simulation
- Benign activity included

### Output

**output/hunt_findings.csv** (All Detections)
- 29 total findings
- Timestamp, host, user
- Detection name and severity
- MITRE technique mapping

**output/credential_dumping_hits.csv** (Filtered View)
- Credential theft specific
- LSASS access events
- Tool usage indicators

**output/lateral_movement_hits.csv** (Filtered View)
- Lateral movement specific
- Network logon analysis
- Pass-the-Hash indicators

**output/timeline.csv** (Chronological)
- Attack timeline
- Sequential events
- Incident response ready

**output/threat_summary.csv** (Statistics)
- Executive metrics
- Severity breakdown
- MITRE technique counts

---

## 🛠️ How to Use This Project

### Run the Analysis
```bash
python src/hunt.py
```

### View Results
```bash
# Windows
type output\hunt_findings.csv

# Linux/Mac
cat output/hunt_findings.csv
```

### Customize Detection
Edit `src/detection_engine.py` to add new detection methods

### Use Your Own Data
```bash
python src/hunt.py --input your_logs.csv --output results/
```

---

## 📞 Support

For questions or issues:
1. Check **[README.md](README.md)** for detailed documentation
2. Review **[QUICK_START.md](QUICK_START.md)** for common issues
3. Examine source code comments for implementation details

---

## 🎓 Learning Path

**Beginner Level:**
1. Run the project (QUICK_START.md)
2. Understand the attack (ATTACK_FLOW.md)
3. Review the findings (output/hunt_findings.csv)

**Intermediate Level:**
1. Study detection logic (src/detection_engine.py)
2. Analyze the dataset (data/logs.csv)
3. Read the full report (report/threat_hunt_report.md)

**Advanced Level:**
1. Customize detection rules
2. Add new MITRE techniques
3. Integrate with SIEM platforms
4. Develop additional data sources

---

## ✅ Project Checklist

- [x] Realistic Windows event log dataset (51 events)
- [x] Python threat hunting framework
- [x] Detection engine with MITRE ATT&CK mapping
- [x] Multiple output formats (CSV)
- [x] Professional investigation report (15 pages)
- [x] Executive brief for leadership
- [x] Complete documentation (README, guides)
- [x] Portfolio skills summary
- [x] Attack flow visualization
- [x] Quick start guide
- [x] Requirements file
- [x] .gitignore for version control
- [x] Tested and working code

---

**Project Status:** ✅ Complete and Production-Ready  
**Last Updated:** March 2024  
**Version:** 1.0
