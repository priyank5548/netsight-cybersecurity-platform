# 🔐 NetSight – Cybersecurity Analysis Platform

## 📌 Overview
NetSight is a multi-module cybersecurity analysis platform designed to perform **digital forensics, threat detection, and system monitoring**.  
It integrates web scanning, malware analysis, network reconnaissance, and host-based monitoring into a single dashboard.

This project was developed as part of a **Digital Forensics Bootcamp** to apply real-world cybersecurity concepts in a practical system.

---

## 🚀 Features

### 🌐 Web & Network Analysis
- URL/IP scanning
- DNS, WHOIS, and IP Geolocation
- SSL/TLS certificate analysis
- Security headers inspection
- Port scanning & service detection

### 🧪 Malware & File Analysis
- File hashing (MD5, SHA256)
- Entropy analysis
- Suspicious string extraction
- PE file analysis (imports, signatures)
- Embedded file detection

### 🧠 Memory & Process Monitoring
- RAM usage analysis
- Suspicious process detection
- Resource monitoring

### 🛡️ System Activity Monitoring
- Process creation & termination tracking
- Network connection monitoring
- File creation, modification, deletion logs
- Real-time system alerts

### 📊 Log Analysis
- Event filtering and searching
- Timeline visualization
- System activity statistics

### 🌐 Network Discovery
- Device discovery in local network
- OS fingerprinting
- Open port and service detection
- SNMP & NetBIOS information

### 🔐 Registry Security Analysis
- Startup persistence detection
- Winlogon hijacking detection
- DLL injection detection
- Credential theft indicators
- Suspicious registry entries identification

### ⚠️ Vulnerability Scanner
- Installed software analysis
- Version-based vulnerability detection
- Risk assessment

### 📊 Dashboard
- Risk scoring system
- Visual representation of results
- Interactive interface

---

## 🛠️ Technologies Used
- Python
- FastAPI
- Streamlit
- socket, requests, dnspython
- pefile, yara, psutil
- BeautifulSoup

---

## 📂 Project Structure
```
NetSight/
│
├── app.py
├── scanner.py
├── web_analyzer.py
├── memory.py
├── network.py
├── registry_scanner.py
├── system_logger.py
├── log_analyzer.py
├── requirements.txt
└── README.md
```

---

## ⚙️ Installation & Setup

### 1. Clone Repository
```
git clone https://github.com/YOUR_USERNAME/netsight-cybersecurity-platform.git
cd netsight-cybersecurity-platform
```

### 2. Create Virtual Environment (Optional)
```
python -m venv venv
venv\Scripts\activate
```

### 3. Install Dependencies
```
pip install -r requirements.txt
```

### 4. Run the Application
```
python app.py
```

### 5. Open in Browser
```
http://127.0.0.1:5000
```

---

## 🎯 Use Cases
- Digital Forensics Analysis
- Cybersecurity Learning & Research
- Network Reconnaissance
- Malware Analysis
- System Monitoring & Incident Detection

---

## 🔮 Future Enhancements
- AI-based threat prediction
- Real-time alerting system
- Cloud deployment
- Threat intelligence API integration

---

## 👨‍💻 Author
Your Name

---

## ⭐ Acknowledgement
Developed during the **Digital Forensics Bootcamp** organized by  
**Gujarat Technological University (GTU)** under the  
**ISEA Project (Ministry of Electronics & IT, Government of India)**.

---

## 📎 License
This project is for educational purposes.