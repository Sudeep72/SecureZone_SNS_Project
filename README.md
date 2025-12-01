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
* **NetworkX** – SDN modeling & topology graphs
* **Collections (deque)** – fast event history and caching

---

## 📁 **Project Structure**

```
securezone/
│── app.py                   # Main Flask app + system initialization
│── test_securezone.py       # Script to test API endpoints
│── templates/
│     └── dashboard.html     # Dashboard frontend
│── static/                  # Optional CSS/JS
│── README.md                # Documentation
│── requirements.txt         # Dependencies
```

---

## 🧪 **Test Script: `test_securezone.py`**

This script automatically tests all major API endpoints exposed by SecureZone.
It sends GET/POST requests to the running Flask server, prints status codes, and displays formatted JSON responses.

### **Endpoints tested**

* `/api/status` – system status
* `/api/run_scan` – quick & deep scans
* `/api/alerts` – recent alerts
* `/api/advanced_metrics` – SSL/DNS/UEBA/protocol metrics
* `/api/detection_layers` – active security layers
* `/api/network` – network topology graph

### **How to use**

Start the SecureZone server:

```bash
python app.py
```

Then run:

```bash
python test_securezone.py
```

This prints structured output for each endpoint and verifies that the system is functioning correctly.

---

## 🏗️ **How It Works**

### **1. Traffic Generation**

Simulated flows include:

* Normal traffic
* Suspicious flows (C2-like, tunneling, bot timing)
* DGA domains
* MITM certificate anomalies
* Insider-like behaviors

### **2. Ensemble Detection Pipeline**

* Feature extraction → scaling
* IsolationForest
* MLP autoencoder classifier
* DBSCAN clustering
* Statistical thresholds
* Rule-based heuristics

An anomaly is flagged if **≥ 2 detectors vote anomaly**.

### **3. Multi-Layer Risk Scoring**

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
* Record isolation events
* Update per-device risk in topology

---

## 📡 **API Endpoints**

| Endpoint                | Description                         |
| ----------------------- | ----------------------------------- |
| `/api/status`           | Full system status + dashboard data |
| `/api/run_scan`         | Run security scan (quick/deep)      |
| `/api/alerts`           | Recent alerts                       |
| `/api/network`          | Network topology graph              |
| `/api/advanced_metrics` | SSL/DNS/UEBA/protocol metrics       |

---

## ▶️ **How to Run**

### **1. Create virtual environment**

```bash
python -m venv venv
source venv/bin/activate   # Linux/macOS
venv\Scripts\activate      # Windows
```

### **2. Install dependencies**

```bash
pip install -r requirements.txt
```

### **3. Start the system**

```bash
python app.py
```

App will be served at:

```
http://localhost:5000
```

---

## 🧩 **Notable Implementation Details**

* `convert_numpy_types` ensures JSON-safe output
* Modular class-based architecture (SSL inspector, DNS analyzer, UEBA, protocol analyzer, threat intel, SDN controller)
* Traffic generation supports diverse threat patterns
* Ensemble detector supports retraining
* Dashboard-ready JSON responses

---

## 🔮 **Future Work**

SecureZone will be further expanded to move beyond simulated environments.
Planned enhancements include:

* **Integration with real-world network traffic** using packet capture (pcap), NetFlow/IPFIX collectors, or live network taps.
* **Testing against real enterprise datasets** to benchmark detection accuracy, false positives, and performance under real load.
* **Refining ML models using real traffic distributions**, enabling better generalization and robustness.
* **Deploying SecureZone in a small-scale real network environment** to evaluate SDN isolation under real operational conditions.
* **Adding support for more protocols**, richer certificate metadata, and expanded UEBA behavioral baselines.

These improvements will transition SecureZone from a research prototype into a more production-capable security platform.

---

## 📜 **License**

This project is intended for **research and educational use only**.
Not production-hardened.

---

## 🙌 **Acknowledgments**

This project integrates concepts from SDN security, machine learning, threat intelligence, and network forensics research.


