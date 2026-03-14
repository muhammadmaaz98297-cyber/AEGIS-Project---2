# AEGIS-Project---2
AEGIS-Grid is a sidecar security layer for Siemens S7-1200 PLCs. It uses a TinyML Isolation Forest and "AEGIS-Gate" logic to correlate S7CommPlus traffic with CPU/RAM stress. Deployed via K8s with 3-node HA, it offers 67ms latency and 1.000 accuracy. This "Marginal Addition" uses hardware state to eliminate false positives from benign HMI bursts.
