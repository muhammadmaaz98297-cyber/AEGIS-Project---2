import requests
import time
import random
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix, roc_curve, auc, classification_report

# --- AEGIS-Grid: Research Evaluation & Visualization Script ---
# This script validates the "Marginal Addition" hypothesis by generating 
# academic-grade metrics and plots for the Thesis Section IV.

# Configuration: Point this to your Minikube Service IP or Localhost if port-forwarded
API_URL = "http://localhost:80/predict" 
SAMPLES_PER_PHASE = 50  # Total 100 samples for statistical significance

def run_evaluation():
    results = []
    
    print("🚀 AEGIS Research Evaluator Started")
    print("--------------------------------------")
    print(f"Target API: {API_URL}")
    print("Collecting data for Thesis Section IV Results...")

    # --- PHASE 1: BENIGN TELEMETRY COLLECTION ---
    print("\n[PHASE 1] Testing Baseline (Benign)...")
    for i in range(SAMPLES_PER_PHASE):
        # Simulating low-volume, high-duration legitimate control traffic
        payload = {
            "Flow Packets/s": random.uniform(5, 25),
            "Flow Duration": random.uniform(0.1, 2.0),
            "Resource_Load": random.uniform(0.05, 0.28) # Low PLC CPU usage
        }
        try:
            resp = requests.post(API_URL, json=payload, timeout=2).json()
            results.append({
                "actual": 0, # Label: Benign
                "predicted": 1 if resp['status'] == "ATTACK" else 0,
                "score": resp['anomaly_score'],
                "load": payload['Resource_Load'],
                "pkts": payload['Flow Packets/s'],
                "latency": resp.get('latency_ms', 0)
            })
            if i % 10 == 0: print(f"  > Logged {i} benign samples...")
        except Exception as e:
            print(f"  > Connection Error: {e}")

    # --- PHASE 2: DDOS INJECTION & CORRELATION ---
    print("\n[PHASE 2] Initiating DDoS Injection (Marginal Stress)...")
    for i in range(SAMPLES_PER_PHASE):
        # Simulating high-volume, low-duration S7CommPlus flood
        payload = {
            "Flow Packets/s": random.uniform(850, 1600),
            "Flow Duration": random.uniform(0.001, 0.03),
            "Resource_Load": random.uniform(0.78, 0.99) # High PLC CPU usage
        }
        try:
            resp = requests.post(API_URL, json=payload, timeout=2).json()
            results.append({
                "actual": 1, # Label: Attack
                "predicted": 1 if resp['status'] == "ATTACK" else 0,
                "score": resp['anomaly_score'],
                "load": payload['Resource_Load'],
                "pkts": payload['Flow Packets/s'],
                "latency": resp.get('latency_ms', 0)
            })
            if i % 10 == 0: print(f"  > Logged {i} attack samples...")
        except Exception as e:
            print(f"  > Connection Error: {e}")

    # Convert results to DataFrame for Analysis
    df = pd.DataFrame(results)
    if df.empty:
        print("❌ Error: No data collected. Ensure the AEGIS service is running.")
        return

    print("\n" + "="*40)
    print("📊 GENERATING ACADEMIC VISUALIZATIONS")
    print("="*40)

    # --- VISUALIZATION 1: CONFUSION MATRIX ---
    plt.figure(figsize=(6,5))
    cm = confusion_matrix(df['actual'], df['predicted'])
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=['Benign', 'DDoS'], 
                yticklabels=['Benign', 'DDoS'])
    plt.title('Figure 4.1: AEGIS-Grid Confusion Matrix')
    plt.ylabel('True Class (Actual State)')
    plt.xlabel('Predicted Class (AEGIS Output)')
    plt.tight_layout()
    plt.savefig('confusion_matrix.png')
    print("✅ Saved: confusion_matrix.png")

    # --- VISUALIZATION 2: ROC CURVE ---
    fpr, tpr, _ = roc_curve(df['actual'], df['score'])
    roc_auc = auc(fpr, tpr)
    plt.figure(figsize=(7,6))
    plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (AUC = {roc_auc:.4f})')
    plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate (FPR)')
    plt.ylabel('True Positive Rate (TPR)')
    plt.title('Figure 4.2: Receiver Operating Characteristic (ROC)')
    plt.legend(loc="lower right")
    plt.grid(alpha=0.3)
    plt.savefig('roc_curve.png')
    print("✅ Saved: roc_curve.png")

    # --- VISUALIZATION 3: DISTRIBUTION PLOT (THE MARGINAL EFFECT) ---
    plt.figure(figsize=(10,6))
    sns.kdeplot(data=df[df['actual']==0], x='score', fill=True, color="green", label='Benign Traffic')
    sns.kdeplot(data=df[df['actual']==1], x='score', fill=True, color="red", label='DDoS Attack')
    plt.axvline(0.75, color='black', linestyle='--', label='AEGIS Threshold (0.75)')
    plt.title('Figure 4.3: Anomaly Score Distribution (Marginal Addition Effect)')
    plt.xlabel('AEGIS Anomaly Score (0.0 to 1.0)')
    plt.ylabel('Density')
    plt.legend()
    plt.savefig('distribution_plot.png')
    print("✅ Saved: distribution_plot.png")

    # --- PRINT SUMMARY FOR THESIS ---
    print("\n" + "="*40)
    print("📜 CLASSIFICATION REPORT FOR SECTION IV")
    print("="*40)
    print(classification_report(df['actual'], df['predicted'], target_names=['Benign', 'DDoS']))
    
    avg_lat = df['latency'].mean()
    print(f"Mean Inference Latency: {avg_lat:.2f} ms")
    print(f"Final AUC Score: {roc_auc:.4f}")
    print("="*40)
    print("Evaluation Complete. All figures exported for LaTeX inclusion.")

if __name__ == "__main__":
    # Ensure dependencies are installed: 
    # pip install requests numpy pandas matplotlib seaborn scikit-learn
    run_evaluation()