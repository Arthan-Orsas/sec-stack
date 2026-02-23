FROM python:3.11-slim

WORKDIR /app
COPY entra_collector.py /app/entra_collector.py

RUN pip install --no-cache-dir requests

CMD ["python", "/app/entra_collector.py"]