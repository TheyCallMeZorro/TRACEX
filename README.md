
# TraceX 🔎

### Graphical Security Log Analyzer

TraceX is a browser-based security log analysis tool designed to help analyze, visualize, and investigate log activity through a modern cybersecurity dashboard.

It parses uploaded log files, extracts useful security information, calculates activity statistics, and detects potentially suspicious behavior such as repeated failed logins, brute-force attempts, scanning activity, unauthorized access, and other security indicators.

---

## ✨ Features

### 📊 Security Dashboard

* Total log entries
* Unique IP addresses
* Unique users
* Failed login attempts
* Suspicious events
* Brute-force alerts
* Log activity timeline
* Top IP addresses
* Log-level distribution
* Top users
* Recent security alerts

### 📄 Log Viewer

* Browse parsed log entries
* View timestamps
* View log severity
* View source IP addresses
* View usernames
* View detected event types
* Inspect complete log messages

### 🔎 Search & Filtering

* Full-text log search
* IP filtering
* Username filtering
* Log-level filtering
* Event filtering
* Reset filters

### 🛡️ Security Detection

TraceX can identify patterns related to:

* Failed authentication
* Brute-force activity
* Suspicious IP behavior
* High-volume activity
* Network scanning
* Privilege escalation
* Unauthorized access
* SQL injection indicators
* Command injection indicators
* Malware indicators
* Suspicious command or process execution
* Security configuration changes

### 📈 Visual Analytics

* Log activity timeline
* IP distribution charts
* Severity distribution charts
* Event distribution charts
* Statistics visualization

### 📑 Reports & Export

* Export analyzed logs as CSV
* Generate security analysis reports
* Keep local scan history

### ⚙️ Settings

* Brute-force detection toggle
* Suspicious-event detection toggle
* Interface animation settings

---

## 🧰 Technologies

* **HTML5**
* **CSS3**
* **JavaScript**
* **Chart.js**
* **Browser File API**
* **LocalStorage**

TraceX currently runs entirely in the browser for log parsing and analysis.

---

## 📁 Project Structure

```text
TraceX/
│
├── index.html
│
├── css/
│   └── style.css
│
├── js/
│   ├── parser.js
│   ├── analyzer.js
│   ├── detector.js
│   ├── charts.js
│   └── app.js
│
├── data/
│   └── sample.log
│
├── assets/
│
├── README.md
└── LICENSE
```

---

## 🚀 Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/YOUR-USERNAME/TraceX.git
```

### 2. Open the project

```bash
cd TraceX
```

### 3. Start a local web server

Using Python:

```bash
python -m http.server 8000
```

### 4. Open TraceX

Open your browser and visit:

```text
http://localhost:8000
```

### 5. Analyze a log

Click:

```text
Open Log
```

and select a supported log file.

TraceX will parse the file and populate the dashboard automatically.

---

## 🧪 Sample Data

A sample log file is included for testing:

```text
data/sample.log
```

The sample contains a mixture of normal activity and security-related events, including failed logins, brute-force patterns, scanning activity, privilege escalation indicators, SQL injection indicators, and malware/backdoor events.

---

## 📄 Supported File Types

TraceX currently accepts:

```text
.log
.txt
.csv
.json
```

Supported formats may contain fields such as:

```text
Timestamp
Level
IP Address
Username
Event
Message
```

TraceX also attempts to recognize common generic, Syslog-style, Apache-style, CSV, and JSON log structures.

---

## 🔐 Security Detection Model

TraceX uses a browser-based rule-driven detection engine.

The analyzer examines log entries for patterns and activity that may indicate suspicious behavior.

Severity levels include:

```text
LOW
MEDIUM
HIGH
CRITICAL
```

Detections are presented through the dashboard, alert views, and generated reports.

> TraceX is an analysis and investigation tool. Detection results should be reviewed and validated by the user before being treated as confirmed security incidents.

---

## 🌐 Deployment

TraceX is designed to run as a static web application, making it suitable for deployment through services that host static Git repositories.

The project can be developed and maintained through GitHub and later published using a static hosting solution.

---

## 🔮 Future Improvements

Possible future versions of TraceX may include:

* Real-time log monitoring
* More advanced threat scoring
* Interactive IP investigation
* Alert investigation pages
* GeoIP visualization
* Authentication and user accounts
* Backend-powered analysis
* Database storage
* Larger log-file processing
* Additional log formats
* SIEM-style correlation rules
* Custom detection rules
* PDF report generation
* Dark/light interface customization

---

## 🎯 Project Goal

TraceX aims to provide a simple, visual, and practical way to investigate security logs without requiring a complex SIEM platform.

It combines:

```text
Parsing
+
Analysis
+
Detection
+
Visualization
+
Reporting
```

into one browser-based security tool.

---

## 👨‍💻 Author

**Zorro**

Built as a cybersecurity-focused web application project.

---

## 📜 License

This project is intended for educational and development purposes.

See the `LICENSE` file for details.
