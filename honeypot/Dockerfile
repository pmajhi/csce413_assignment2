FROM python:3.11-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Install paramiko
RUN pip install --no-cache-dir paramiko

COPY honeypot.py logger.py ./

RUN mkdir -p /app/logs
EXPOSE 22

CMD ["python3", "honeypot.py"]
