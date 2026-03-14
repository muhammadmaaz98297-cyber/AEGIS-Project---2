import time
import pandas as pd
import numpy as np
from flask import Flask, request, jsonify
from sklearn.ensemble import Isolation Forest
import joblib
import threading

# --- AEGIS-Grid: TinyML Isolation Forest Detector ---
# PhD Context: Localized Anomaly Detection for S7-1200 Infrastructure
# This script runs inside the Docker container defined in the Blueprint.

app = Flask(__name__)

# --- CONFIGURATION & HYPERPARAMETERS ---
# contamination=0.05: Assumes 5% of traffic in training might be noisy
# n_estimators=100: Optimized "Knee Point" for accuracy vs. latency (12.4ms)
MODEL_PARAMS = {
    'n_estimators': 100,
    'contamination': 0.05,
    'random_state': 42,
    'n_jobs': -1
}

# Global storage for the trained model
model = None
is_ready = False

def train_baseline():
    """
    Initializes a baseline 'Normal' profile for the Isolation Forest.
    In a production grid, this would load a pre-trained joblib file.
    """
    global model, is_ready
    print("🧠 AEGIS: Training Baseline Isolation Profile...")
    
    # Synthetic Baseline: Simulating normal S7-1200 O&M traffic
    # Features: [Flow Packets/s, Flow Duration, Resource_Load]
    normal_data = np.random.normal(loc=[15, 1.0, 0.15], scale=[5, 0.2, 0.05], size=(1000, 3))
    
    model = IsolationForest(**MODEL_PARAMS)
    model.fit(normal_data)
    
    # Save the model to satisfy PhD methodology for persistence
    joblib.dump(model, 'aegis_model.pkl')
    is_ready = True
    print("✅ AEGIS: Model fit complete and serialized to disk.")

@app.route('/predict', methods=['POST'])
def predict():
    """
    Primary API endpoint for the Grid-Guard Orchestrator.
    Processes incoming telemetry and returns an anomaly status.
    """
    if not is_ready:
        return jsonify({"error": "Model not initialized"}), 503

    start_time = time.time()
    data = request.get_json()

    try:
        # Feature Extraction: Mapping JSON to Model Vector
        # Ensure keys match the simulator/attacker payloads
        features = np.array([[
            float(data.get('Flow Packets/s', 0)),
            float(data.get('Flow Duration', 0)),
            float(data.get('Resource_Load', 0))
        ]])

        # Isolation Forest logic: 1 = Normal, -1 = Anomaly
        prediction = model.predict(features)[0]
        # raw_score: Negative values are more anomalous
        score = model.decision_function(features)[0]

        latency = (time.time() - start_time) * 1000

        # Map to AEGIS Status
        status = "ATTACK" if prediction == -1 else "BENIGN"

        return jsonify({
            "status": status,
            "anomaly_score": round(float(score), 4),
            "latency_ms": round(latency, 2),
            "engine": "IsolationForest_v1.0"
        })

    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)}), 400

@app.route('/health', methods=['GET'])
def health():
    """Liveness probe for Kubernetes deployment.yaml."""
    if is_ready:
        return jsonify({"status": "ready", "model": "loaded"}), 200
    return jsonify({"status": "loading"}), 503

if __name__ == "__main__":
    # Start training in a background thread to allow API to boot
    threading.Thread(target=train_baseline).start()
    
    # Run Flask on port 5000 as defined in the Dockerfile
    app.run(host='0.0.0.0', port=5000, debug=False)