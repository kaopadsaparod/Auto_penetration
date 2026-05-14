# ============================================================
# AI Pentesting Agent — Docker Image
# ============================================================
# Includes: Python 3.12, nmap, gobuster, sqlmap, metasploit
# ============================================================

FROM python:3.12-slim

# Avoid interactive prompts during build
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies and security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    gobuster \
    sqlmap \
    git \
    curl \
    wget \
    net-tools \
    iputils-ping \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Install Metasploit Framework
RUN curl -fsSL https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall \
    && chmod +x /tmp/msfinstall \
    && /tmp/msfinstall \
    && rm /tmp/msfinstall \
    || echo "MSF install failed — will work without it"

# Create app directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy agent code
COPY agent/ ./agent/
COPY config.yaml .

# Create data directories
RUN mkdir -p data/chroma

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Entry point
CMD ["python", "-m", "agent.main"]
