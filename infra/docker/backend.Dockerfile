# Backend image (api / worker / scheduler / migrate share it).
#
# Offline build: every Python package comes from vendor/wheels (populated by
# scripts/vendor.*) and is verified against the hashes in requirements*.txt.
# No network access is needed beyond having the pinned base image loaded locally.
# (No "# syntax=" directive on purpose: it would pull a BuildKit frontend image.)

ARG PYTHON_IMAGE=python:3.12.15-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258

FROM ${PYTHON_IMAGE} AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_NO_INPUT=1

# ---- runtime dependencies, hash-verified, no index ----
FROM base AS deps
COPY vendor/wheels /wheels
COPY backend/requirements.txt /tmp/requirements.txt
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-index --find-links /wheels --require-hashes \
        -r /tmp/requirements.txt

# ---- + dev/test tooling (used only by the test target) ----
FROM deps AS dev-deps
COPY backend/requirements-dev.txt /tmp/requirements-dev.txt
RUN /opt/venv/bin/pip install --no-index --find-links /wheels --require-hashes \
        -r /tmp/requirements.txt -r /tmp/requirements-dev.txt

# ---- production image ----
FROM base AS runtime
RUN groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app
COPY --from=deps /opt/venv /opt/venv
WORKDIR /srv
COPY backend/alembic.ini ./
COPY backend/alembic ./alembic
COPY backend/app ./app
RUN /opt/venv/bin/python -m compileall -q app alembic /opt/venv/lib
ENV PATH=/opt/venv/bin:$PATH
USER app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4).status == 200 else 1)"]
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--forwarded-allow-ips", "*", "--no-server-header", "--no-date-header"]

# ---- test / CI image: runtime + tooling + tests + the FMC mock ----
FROM runtime AS test
USER root
COPY --from=dev-deps /opt/venv /opt/venv
COPY backend/pyproject.toml backend/requirements.txt backend/requirements-dev.txt ./
COPY backend/tests ./tests
COPY fmc-mock /srv/fmc-mock
ENV PYTHONPATH=/srv:/srv/fmc-mock \
    PYTHONDONTWRITEBYTECODE=1
RUN chown -R app:app /srv
USER app
CMD ["pytest"]
