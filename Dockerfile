FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install only minimal web requirements to reduce image size
COPY requirements-web.txt /app/
RUN pip install --no-cache-dir -r requirements-web.txt \
 && pip install --no-cache-dir gunicorn

# Copy app code (exclude large artifacts via .dockerignore)
COPY . /app

# Create non-root user
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 5000
# Use Python for healthcheck to avoid installing curl
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD python - << 'PY'
import sys,urllib.request
try:
    with urllib.request.urlopen('http://localhost:5000/', timeout=3) as r:
        sys.exit(0 if r.status==200 else 1)
except Exception:
    sys.exit(1)
PY

CMD ["gunicorn", "-w", "2", "-k", "gthread", "--threads", "4", "--keep-alive", "30", "--timeout", "120", "-b", "0.0.0.0:5000", "app:app"]