FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Expose honeypot ports
EXPOSE 21 22 23 80 3389 5000

# Default to running main honeypot
CMD ["python", "honeyPot.py"]
