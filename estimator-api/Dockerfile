# syntax=docker/dockerfile:1.7
FROM --platform=linux/amd64 sagemath/sagemath@sha256:2401ffa8e9fc85c7ea17d3649bde5958b4dbf0858b3e504098c4102720151711

LABEL org.opencontainers.image.title="lattice-security estimator-api" \
      org.opencontainers.image.description="Internal SageMath lattice-estimator adapter" \
      org.opencontainers.image.licenses="LGPL-3.0-or-later" \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.base.name="sagemath/sagemath:10.9" \
      org.opencontainers.image.source="https://github.com/malb/lattice-estimator"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/estimator-api/src:/app/estimator \
    ESTIMATOR_CLEANUP_GRACE_SECONDS=15

WORKDIR /app

COPY --chown=sage:sage estimator-api/requirements.lock /app/estimator-api/requirements.lock
RUN sage -pip install --no-cache-dir --require-hashes \
    -r /app/estimator-api/requirements.lock

# Preserve the complete pinned LGPLv3+ upstream source and its version notice.
COPY --chown=sage:sage estimator/ /app/estimator/
COPY --chown=sage:sage estimator-api/src/ /app/estimator-api/src/
COPY --chown=sage:sage estimator-api/THIRD_PARTY_NOTICES.md /app/THIRD_PARTY_NOTICES.md

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD sage -python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3)" || exit 1

USER sage
CMD ["sage", "-python", "-m", "uvicorn", "estimator_api.app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--no-access-log"]
