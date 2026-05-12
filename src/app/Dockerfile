FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Create restricted service user
RUN groupadd -g 10001 esg_user && \
    useradd -u 10001 -g esg_user -s /bin/bash esg_user

WORKDIR /app

# Dependency layer
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY phishing_detector.joblib .

# Application layer
COPY --chown=esg_user:esg_user . .


USER esg_user

EXPOSE 8000

# Gunicorn provides resilience against DoS
CMD ["python", "-m", "gunicorn", "-w", "4", "-k", "uvicorn.workers.UvicornWorker", "main:app", "--bind", "0.0.0.0:8000"]