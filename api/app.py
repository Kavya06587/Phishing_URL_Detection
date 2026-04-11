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

rf     = joblib.load(os.path.join(BASE, 'rf_model.pkl'))
iso    = joblib.load(os.path.join(BASE, 'iso_model.pkl'))
scaler = joblib.load(os.path.join(BASE, 'scaler.pkl')) 

with open(os.path.join(BASE, 'feature_names.json')) as f:
    feature_names = json.load(f)

with open(os.path.join(BASE, 'metadata.json')) as f:
    metadata = json.load(f)

THRESHOLD = metadata.get('optimal_threshold', 0.65)

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
        'status':    'running',
        'threshold': THRESHOLD,
        'features':  len(feature_names)
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
        vector   = []
        missing  = []

        for name in feature_names:
            if name in features:
                vector.append(float(features[name]))
            else:
                vector.append(0.0)
                missing.append(name)

        X_raw = np.array(vector).reshape(1, -1)

        rf_prob  = rf.predict_proba(X_raw)[0][1]
        rf_label = int(rf_prob >= THRESHOLD)

        iso_raw   = iso.predict(X_raw)[0]
        iso_label = int(iso_raw == -1)   # -1 = anomaly → phishing

        final = int((rf_prob >= THRESHOLD) or (iso_label == 1 and rf_prob >= 0.45))

        # Get domain age for display / reasons (not used in prediction)
        domain_age = get_domain_age(data['url'])

        # ── CONFIDENCE / RISK LEVEL ──
        if rf_prob >= 0.85:
            confidence = 'HIGH RISK 🚨'
            risk_level = 'HIGH'

        elif rf_prob >= THRESHOLD:
            confidence = 'MEDIUM RISK ⚠'
            risk_level = 'MEDIUM'

        elif iso_label == 1:
            # ISO flagged it as anomalous even though RF probability is
            # below the main threshold — treat as suspicious
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

        if len(missing) > 10:
            reasons.append(
                f"Warning: {len(missing)} features missing — prediction may be unreliable"
            )

        return jsonify({
            'url':              data['url'],
            'rf_probability':   round(float(rf_prob), 4),
            'rf_prediction':    'phishing' if rf_label else 'legitimate',
            'iso_prediction':   'phishing' if iso_label else 'legitimate',
            'final':            'phishing' if final else 'legitimate',
            'confidence':       confidence,
            'risk_level':       risk_level,
            'domain_age_days':  domain_age,
            'threshold':        THRESHOLD,
            'missing_features': len(missing),
            'missing_names':    missing if missing else [],
            'reasons':          reasons
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ── FEATURE LIST ──
@app.route('/features', methods=['GET'])
def get_features():
    return jsonify({
        'features': feature_names,
        'count':    len(feature_names)
    })


if __name__ == '__main__':
    app.run(debug=True, port=5000)