AEGIS-Grid Framework: Resource-Aware DDoS Mitigation for S7-1200 PLCs

📌 Project Overview

AEGIS-Grid is a decentralized cybersecurity framework developed as part of a doctoral study on Smart Grid resilience. It introduces a "Marginal Addition" logic to the Siemens S7-1200 PLC environment, using TinyML and Kubernetes to distinguish between malicious DDoS attacks and legitimate industrial traffic bursts.

Core Features

Hardware-Gated Detection: Cross-correlates S7CommPlus network flows with internal PLC CPU/RAM telemetry.

TinyML Isolation Forest: Unsupervised anomaly detection with a footprint under 150MB.

Resilient Orchestration: Self-healing Kubernetes deployment with auto-recovery for critical infrastructure.

Low Latency: Optimized for deterministic OT environments (average detection in <70ms).

📁 Repository Structure

/src/detector.py: The core TinyML engine and Flask-based prediction API.

/deploy/deployment.yaml: Kubernetes manifests for edge-node deployment.

/simulators/aegis_master_evaluator.py: Multi-layered research evaluator for performance benchmarking.

/simulators/attack_simulator.py: Adversarial injection script for S7CommPlus DDoS vectors.

Dockerfile: Blueprint for building the AEGIS sidecar image.

🚀 Getting Started

Prerequisites

Docker & Kubernetes (Minikube or Kind)

Python 3.11+

S7-1200 PLC or PLCSIM Advanced (for telemetry stream)

Installation & Deployment

Clone the repository:

git clone [https://github.com/yourusername/AEGIS-Grid.git](https://github.com/yourusername/AEGIS-Grid.git)
cd AEGIS-Grid


Build the container:

docker build -t aegis-detector:latest .


Deploy to Kubernetes:

kubectl apply -f deployment.yaml


Verify Service:

kubectl get pods -l app=aegis-detector


📊 Evaluation Results

The framework achieved a 1.000 Accuracy and 0.0 False Positive Rate by utilizing the AEGIS-Gate logic. Detailed visual analysis (ROC Curves, Confusion Matrices, and Epoch Progression) can be generated using the aegis_master_evaluator.py script.

📜 Citation

If you use this artefact in your research, please cite:

AEGIS-Grid Framework: A Marginal Addition for Siemens S7-1200 PLC Cyber-Resilience. PhD Thesis.

📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
