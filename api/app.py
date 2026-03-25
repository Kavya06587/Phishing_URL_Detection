from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import json
import numpy as np
import os
import whois
from datetime import datetime
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)

# ── Load models ──
BASE = os.path.join(os.path.dirname(__file__), '..', 'models')

rf  = joblib.load(os.path.join(BASE, 'rf_model.pkl'))
iso = joblib.load(os.path.join(BASE, 'iso_model.pkl'))

with open(os.path.join(BASE, 'feature_names.json')) as f:
    feature_names = json.load(f)

with open(os.path.join(BASE, 'metadata.json')) as f:
    metadata = json.load(f)

# 🔥 Updated threshold
THRESHOLD = 0.75

print(f"Models loaded. Threshold: {THRESHOLD}")
print(f"Features expected: {len(feature_names)}")


# ── DOMAIN AGE FUNCTION ──
def get_domain_age(url):
    try:
        hostname = urlparse(url).hostname
        w = whois.whois(hostname)

        created = w.creation_date
        if isinstance(created, list):
            created = created[0]

        if created:
            return (datetime.now() - created).days

    except:
        pass

    return 500  # neutral fallback


# ── HEALTH CHECK ──
@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'running',
        'threshold': THRESHOLD,
        'features': len(feature_names)
    })


# ── MAIN PREDICTION ──
@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()

        if 'features' not in data:
            return jsonify({'error': 'No features provided'}), 400

        if 'url' not in data:
            return jsonify({'error': 'No URL provided'}), 400

        # ── Build feature vector ──
        features = data['features']
        vector = []
        missing = []

        for name in feature_names:
            if name in features:
                vector.append(float(features[name]))
            else:
                vector.append(0.0)
                missing.append(name)

        X = np.array(vector).reshape(1, -1)

        # ── RF Prediction ──
        rf_prob = rf.predict_proba(X)[0][1]

        # ── DOMAIN AGE ADJUSTMENT (🔥 KEY FIX) ──
        domain_age = get_domain_age(data['url'])

        if domain_age < 30:
            rf_prob += 0.15   # new domain → risky
        elif domain_age > 365:
            rf_prob -= 0.1    # old domain → safer

        rf_prob = min(max(rf_prob, 0), 1)  # clamp between 0–1

        rf_label = int(rf_prob >= THRESHOLD)

        # ── Isolation Forest (ONLY FOR SIGNAL) ──
        iso_raw = iso.predict(X)[0]
        iso_label = int(iso_raw == -1)

        # ── FINAL DECISION (ONLY RF) ──
        final = rf_label

        # ── CONFIDENCE / RISK LEVEL ──
        if rf_prob >= 0.85:
            confidence = 'HIGH RISK 🚨'
            risk_level = 'HIGH'

        elif rf_prob >= THRESHOLD:
            confidence = 'MEDIUM RISK ⚠'
            risk_level = 'MEDIUM'

        elif iso_label == 1:
            confidence = 'SUSPICIOUS ⚠ (unusual pattern)'
            risk_level = 'SUSPICIOUS'

        elif rf_prob >= 0.45:
            confidence = 'LOW RISK'
            risk_level = 'LOW'

        else:
            confidence = 'SAFE'
            risk_level = 'SAFE'

        # ── REASONS (Explainability) ──
        reasons = []

        if rf_prob >= THRESHOLD:
            reasons.append("High phishing probability (ML model)")

        if iso_label == 1:
            reasons.append("Unusual URL structure detected")

        if domain_age < 30:
            reasons.append("Very new domain")

        if domain_age > 365:
            reasons.append("Old trusted domain")

        return jsonify({
            'url': data['url'],
            'rf_probability': round(float(rf_prob), 4),
            'rf_prediction': 'phishing' if rf_label else 'legitimate',
            'iso_prediction': 'phishing' if iso_label else 'legitimate',
            'final': 'phishing' if final else 'legitimate',
            'confidence': confidence,
            'risk_level': risk_level,
            'domain_age_days': domain_age,
            'threshold': THRESHOLD,
            'missing_features': len(missing),
            'reasons': reasons
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ── FEATURE LIST ──
@app.route('/features', methods=['GET'])
def get_features():
    return jsonify({
        'features': feature_names,
        'count': len(feature_names)
    })


if __name__ == '__main__':
    app.run(debug=True, port=5000)