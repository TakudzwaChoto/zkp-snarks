FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY snark_prover.py /app/
RUN pip install --no-cache-dir flask

EXPOSE 5001
CMD ["python", "snark_prover.py"]