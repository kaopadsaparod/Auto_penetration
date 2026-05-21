# ============================================================
# VibeShop — Vulnerable Target Lab Environment
# ============================================================
FROM python:3.12-slim

WORKDIR /app

# Install dependencies
RUN pip install --no-cache-dir flask

# Copy target code
COPY . .

# Run the Flask app on port 80 (to map properly to our allowed ports)
EXPOSE 80

ENV FLASK_ENV=development
ENV FLASK_DEBUG=1
ENV PYTHONUNBUFFERED=1

CMD ["python", "app.py"]
