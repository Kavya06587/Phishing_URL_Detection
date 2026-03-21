from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import json
import numpy as np
import os

app = Flask(__name__)
CORS(app)  # allows Chrome extension to call this API

# ── Load models once at startup ──
BASE   = os.path.join(os.path.dirname(__file__), '..', 'models')

rf     = joblib.load(os.path.join(BASE, 'rf_model.pkl'))
iso    = joblib.load(os.path.join(BASE, 'iso_model.pkl'))

with open(os.path.join(BASE, 'feature_names.json')) as f:
    feature_names = json.load(f)

with open(os.path.join(BASE, 'metadata.json')) as f:
    metadata = json.load(f)

THRESHOLD = metadata['optimal_threshold']  # 0.65

print(f"Models loaded. Threshold: {THRESHOLD}")
print(f"Features expected: {len(feature_names)}")

# ── Health check ──
@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status':    'running',
        'threshold': THRESHOLD,
        'features':  len(feature_names)
    })

# ── Main prediction endpoint ──
@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()

        # Validate input
        if 'features' not in data:
            return jsonify({'error': 'No features provided'}), 400

        if 'url' not in data:
            return jsonify({'error': 'No URL provided'}), 400

        # Build feature vector in correct order
        features = data['features']
        vector   = []

        missing = []
        for name in feature_names:
            if name in features:
                vector.append(float(features[name]))
            else:
                vector.append(0.0)  # default for missing features
                missing.append(name)

        if missing:
            print(f"Warning: {len(missing)} missing features, defaulted to 0")

        # Convert to numpy array
        X = np.array(vector).reshape(1, -1)

        # ── Random Forest prediction ──
        rf_prob    = rf.predict_proba(X)[0][1]
        rf_label   = int(rf_prob >= THRESHOLD)

        # ── Isolation Forest prediction ──
        iso_raw    = iso.predict(X)[0]
        iso_label  = int(iso_raw == -1)  # -1 = anomaly = phishing

        # ── Combined prediction ──
        combined   = int(rf_label == 1 or iso_label == 1)

        # ── Confidence level ──
        if rf_prob >= 0.85:
            confidence = 'HIGH'
        elif rf_prob >= 0.65:
            confidence = 'MEDIUM'
        elif rf_prob <= 0.15:
            confidence = 'SAFE'
        else:
            confidence = 'LOW RISK'

        return jsonify({
            'url':           data['url'],
            'rf_probability': round(float(rf_prob), 4),
            'rf_prediction':  'phishing' if rf_label else 'legitimate',
            'iso_prediction': 'phishing' if iso_label else 'legitimate',
            'final':          'phishing' if combined else 'legitimate',
            'confidence':     confidence,
            'threshold':      THRESHOLD,
            'missing_features': len(missing)
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── Feature list endpoint ──
# Chrome extension can call this to know which features to extract
@app.route('/features', methods=['GET'])
def get_features():
    return jsonify({
        'features': feature_names,
        'count':    len(feature_names)
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)
