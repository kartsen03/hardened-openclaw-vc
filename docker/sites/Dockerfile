FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
WORKDIR /app
COPY docker/sites/server.py docker/model-relay/relay.py ./
COPY docker/sites/www/ /www/
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
# Port 80 needs CAP_NET_BIND_SERVICE as non-root; compose adds only that capability.
USER 10001:10001
CMD ["python", "-I", "server.py"]
