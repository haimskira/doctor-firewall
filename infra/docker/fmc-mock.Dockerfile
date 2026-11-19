# FMC 10.1 emulator — development and tests ONLY. Never part of the production bundle.
ARG PYTHON_IMAGE=python:3.12.16-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df

FROM ${PYTHON_IMAGE} AS deps
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
COPY vendor/wheels /wheels
COPY fmc-mock/requirements.txt /tmp/requirements.txt
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-index --find-links /wheels --require-hashes \
        -r /tmp/requirements.txt

FROM ${PYTHON_IMAGE}
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH=/opt/venv/bin:$PATH
RUN groupadd --system --gid 10002 mock \
 && useradd --system --uid 10002 --gid mock --no-create-home --shell /usr/sbin/nologin mock
COPY --from=deps /opt/venv /opt/venv
WORKDIR /srv
COPY fmc-mock/fmc_mock ./fmc_mock
USER mock
EXPOSE 443
CMD ["uvicorn", "fmc_mock.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "443", \
     "--ssl-certfile", "/certs/fmc-mock.pem", "--ssl-keyfile", "/certs/fmc-mock.key", \
     "--no-server-header"]
