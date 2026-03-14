# Use a lightweight Python base to minimize resource usage on the Grid Edge
FROM python:3.11-slim

# Set the working directory inside the container
WORKDIR /app

# Install system-level dependencies required for Scikit-Learn and TinyML math
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy the requirements file into the container
COPY requirements.txt .

# Install Python libraries (Flask, Pandas, Scikit-Learn, Joblib, Pyarrow)
RUN pip install --no-cache-dir -r requirements.txt

# Copy the actual AEGIS-Grid Detector script
COPY detector.py .

# Expose the port used by the Grid-Guard Orchestrator API
EXPOSE 5000

# PhD Metadata: Identifying the artefact version and its target environment
LABEL version="1.0"
LABEL description="AEGIS-Grid TinyML Detector for Siemens S7-1200 Integration"
LABEL framework="Grid-Guard Orchestrator"

# Command to start the Anomaly Detection service
CMD ["python", "detector.py"]