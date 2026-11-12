FROM python:3.12-slim-bookworm
RUN useradd --create-home --uid 10001 auditor && mkdir -p /app /output /config \
    && chown -R auditor:auditor /app /output
COPY src /app/src
WORKDIR /app
USER 10001:10001
ENTRYPOINT ["python", "-m", "src.auditor"]
