FROM python:3.12.7-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /opt/avm
COPY requirements.txt .
ARG PIP_INDEX_URL=https://pypi.org/simple
RUN PIP_INDEX_URL="${PIP_INDEX_URL}" pip install --no-cache-dir -r requirements.txt \
    && groupadd -r avm && useradd -r -g avm -u 10001 avm
COPY avm/ ./avm/
USER 10001:10001
CMD ["python", "-m", "avm.worker"]
