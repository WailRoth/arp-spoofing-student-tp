FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir flask

COPY server.py .

CMD ["python", "server.py"]
