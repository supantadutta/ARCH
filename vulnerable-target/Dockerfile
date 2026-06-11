# Minimal, dependency-free demo scan target. DISABLED BY DEFAULT.
# Only built/run when the compose `vuln` profile is explicitly enabled.
FROM python:3.12-slim
WORKDIR /app
COPY server.py .
EXPOSE 9000
CMD ["python", "server.py"]
