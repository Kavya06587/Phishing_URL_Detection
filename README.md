# 🛡️ Phishing URL Detection

A production-ready machine learning pipeline for detecting phishing URLs with **94.8% recall** and **0.993 AUC**, featuring a Chrome extension for real-time browser protection and SHAP-based explainability.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![scikit-learn](https://img.shields.io/badge/scikit--learn-ML-orange?logo=scikit-learn)
![Flask](https://img.shields.io/badge/Flask-API-lightgrey?logo=flask)
![Chrome Extension](https://img.shields.io/badge/Chrome-Extension-yellow?logo=googlechrome)
![License](https://img.shields.io/badge/License-MIT-green)

---

## 📊 Key Results

| Metric | Value |
|---|---|
| **AUC** | 0.9934 |
| **Recall** | 93.8% (threshold-tuned) |
| **Combined Recall** | 94.8% (RF + Isolation Forest) |
| **False Positive Rate** | 1.9% |
| **5-Fold CV AUC** | 0.9934 ± 0.0012 |

---

## 📋 Overview

Phishing attacks remain one of the most prevalent cybersecurity threats. This project addresses the challenge with a **production-ready ML pipeline** that:

- Analyzes **87 features** across lexical patterns, obfuscation signals, and reputation metrics
- Compares **Logistic Regression vs. Random Forest** classifiers
- Uses **Isolation Forest** for zero-day anomaly detection
- Provides **SHAP-based explanations** for every prediction
- Deploys via a **Chrome extension** for real-time URL protection

---

## 🔍 Key Insight

Reputation signals (`google_index`, `page_rank`, `domain_age`) consistently outperform lexical features — confirmed by **three independent methods**:

- Correlation analysis (0.731)
- Random Forest feature importance
- SHAP mean absolute values

---

## 🗂️ Project Structure

```
Phishing_URL_Detection/
│
├── Phishing_detection.ipynb   # Main ML pipeline notebook
├── api/                       # Flask backend API
├── extension/                 # Chrome extension source
├── models/                    # Saved trained models
├── requirements.txt           # Python dependencies
└── README.md
```

---

## ⚙️ Tech Stack

| Component | Technology |
|---|---|
| ML Models | Scikit-learn (Random Forest, Logistic Regression, Isolation Forest) |
| Explainability | SHAP |
| API Backend | Flask, Flask-CORS |
| Feature Extraction | tldextract, whois, requests |
| Visualization | Matplotlib, Seaborn |
| Browser Integration | Chrome Extension (JS) |
| Model Persistence | Joblib |

---

## 🚀 Getting Started

### 1. Clone the repository
```bash
git clone https://github.com/Kavya06587/Phishing_URL_Detection.git
cd Phishing_URL_Detection
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the notebook
```bash
jupyter notebook Phishing_detection.ipynb
```

### 4. Start the Flask API
```bash
cd api
python app.py
```

### 5. Load the Chrome Extension
- Open Chrome and go to `chrome://extensions/`
- Enable **Developer Mode**
- Click **Load unpacked** and select the `extension/` folder

---

## 🧠 ML Pipeline

```
Raw URLs
   ↓
Feature Extraction (87 features)
   ↓
Preprocessing & Scaling
   ↓
┌─────────────────┬──────────────────┐
│  Random Forest  │ Isolation Forest │
│  (Supervised)   │ (Anomaly/ZeroDay)│
└─────────────────┴──────────────────┘
   ↓
Threshold Tuning (maximize recall)
   ↓
SHAP Explainability
   ↓
Flask API → Chrome Extension
```

---

## 📦 Feature Categories

| Category | Examples |
|---|---|
| Lexical | URL length, special character count, digit ratio |
| Obfuscation | IP in URL, shortening services, `@` symbol |
| Reputation | `google_index`, `page_rank`, `domain_age` |

---

## 🔮 Future Scope

- Deep learning models (LSTM/BERT) for URL sequence analysis
- Real-time dataset updates with active learning
- Firefox and Edge extension support
- Dashboard for monitoring flagged URLs

---

## 👩‍💻 Author

**Kavya** — [GitHub](https://github.com/Kavya06587)

---

## 📄 License

This project is licensed under the MIT License.
