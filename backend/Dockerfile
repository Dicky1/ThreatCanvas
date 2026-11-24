FROM python:3.13-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Download the full MITRE ATT&CK Enterprise STIX bundle at build time so the
# container validates against complete, current ATT&CK data (and regenerates
# the compact catalog from it). If the build has no network access the image
# still works with the committed app/data/attack_catalog.json.
# Disable with: docker build --build-arg FETCH_ATTACK_DATA=false .
ARG FETCH_ATTACK_DATA=true
RUN if [ "$FETCH_ATTACK_DATA" = "true" ]; then \
        python scripts/fetch_attack_data.py \
        || echo "WARNING: ATT&CK download failed; using bundled attack_catalog.json"; \
    fi

# Run as an unprivileged user.
RUN useradd --create-home --uid 10001 threatcanvas && chown -R threatcanvas /app
USER threatcanvas

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
