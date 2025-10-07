FROM python:3.11-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends tcpdump iproute2 \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir scapy

WORKDIR /app

COPY attacker.py .

CMD ["python", "attacker.py"]
