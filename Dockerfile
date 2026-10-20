FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# ponytail: runserver is fine for the scaffold; swap for gunicorn before any real deployment.
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
