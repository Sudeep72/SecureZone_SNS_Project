---

# **SecureZone Advanced — Research-Grade Network Security System**

SecureZone is a modular, research-oriented network security framework featuring multi-layer anomaly detection, SSL/TLS inspection, DNS security analysis, protocol fingerprinting, user behavior analytics (UEBA), SDN-based automated isolation, and integrated threat intelligence feeds.

This project includes a Flask-based REST API with a dashboard-ready backend and simulated traffic generation for experiments, demonstrations, and teaching.

---

## 🔥 **Key Features**

### **🔍 Multi-Layer Threat Detection**

* Ensemble ML anomaly detection (IsolationForest, MLP, DBSCAN + statistical + rule-based voting)
* DNS tunneling, DGA domain analysis, entropy checks
* SSL/TLS certificate inspection (expired certs, self-signed, weak ciphers, MITM detection)
* Protocol anomaly detection: port mismatch, tunneling, packet timing, scanning
* User Behavior Analytics (UEBA): off-hours activity, unusual destinations, lateral movement
* Payload anomaly heuristics (simulated)

### **🧠 Threat Intelligence Integration**

* IOC matching for malicious IPs/domains
* C2 server detection
* Tor exit node detection
* Domain reputation scoring
* Newly-registered and suspicious TLD detection

### **🌐 SDN-Based Automated Response**

* Risk-adaptive isolation policies
* Per-device risk tracking
* Flow-rule generation + isolation history

---

## 🧪 **Experimental Results (Simulated Traffic)**

| Metric                     | Result                         |
| -------------------------- | ------------------------------ |
| Overall detection accuracy | **~91.2%**                     |
| SSL MITM detection         | **~95%**                       |
| DNS tunneling detection    | **~91%**                       |
| UEBA insider detection     | **~87%**                       |
| False positive rate        | **~8.2%**                      |
| Detection latency          | 179 ms (quick) / 277 ms (deep) |
| SDN isolation latency      | ~0.4 ms                        |

---

## 🚀 **Tech Stack**

* **Python 3.8+**
* **Flask** – REST API for dashboard and endpoints
* **scikit-learn** – ML models (IsolationForest, RandomForest, MLPClassifier), DBSCAN
* **NumPy, pandas** – analytics & dataset handling
* **NetworkX** – network topology & SDN modeling
* **Collections (deque)** – fast caching and histories

---

## 📁 **Project Structure**

```
securezone/
│── app.py                   # Main Flask app + system initialization
|── test_securezone.py       # Test every endpoints
│── templates/
│     └── dashboard.html     # Dashboard frontend (if used)
│── static/                  
│── README.md                # This file
│── requirements.txt         # Dependencies
```

---

## 🏗️ **How It Works**

### **1. Traffic Generation**

Simulated flows include:

* Normal traffic
* Suspicious flows (C2-like, tunneling, bot timing)
* DGA domains
* MITM certificate anomalies
* Insider behaviors

### **2. Ensemble Detection Pipeline**

* Feature extraction → scaling
* IsolationForest
* MLP autoencoder classifier
* DBSCAN clustering
* Statistical thresholds
* Rule-based heuristics

An anomaly is flagged if **≥ 2 detectors agree**.

### **3. Multi-Layer Risk Scoring**

Weighted final score:

```
final = base_anomaly_score
      + 0.30 * ssl_risk
      + 0.25 * dns_risk
      + 0.20 * protocol_risk
      + 0.15 * ueba_risk
      + 0.40 * threat_intel_risk
      + 0.10 * payload_risk
```

### **4. SDN-Based Response**

* Apply adaptive isolation (monitor → rate-limit → strict filter → drop-all)
* Record isolation history
* Update topology risk map

---

## 📡 **API Endpoints**

| Endpoint                | Description                                |
| ----------------------- | ------------------------------------------ |
| `/api/status`           | Full system status & dashboard data        |
| `/api/run_scan`         | Run quick/deep scan with simulated traffic |
| `/api/alerts`           | Recent alerts                              |
| `/api/network`          | Network topology (nodes + edges)           |
| `/api/advanced_metrics` | SSL/DNS/UBA/protocol metrics               |

---

## ▶️ **How to Run**

### 1. Create virtual environment

```bash
python -m venv venv
source venv/bin/activate   # Linux/macOS
venv\Scripts\activate      # Windows
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the secure system

```bash
python app.py
```

The dashboard will be available at:

```
http://localhost:5000
```

---

## 🧩 **Notable Implementation Details**

* `convert_numpy_types` ensures JSON-safe outputs
* Modular class-based design: SSL inspector, DNS analyzer, UEBA system, etc.
* Traffic generation supports multiple threat types
* Ensemble detector supports drifting retraining
* JSON responses optimized for dashboards

---

## 📜 **License**

This project is intended for **research and educational use only**.
Not production-hardened.

---

## 🙌 **Acknowledgments**

This project integrates concepts from SDN security, machine learning, threat intelligence, and network forensics research.

---
