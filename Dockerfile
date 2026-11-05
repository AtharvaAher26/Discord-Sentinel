FROM python:3.12-slim

WORKDIR /app

# dependencies first - layer caching keeps rebuilds fast
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# SQLite lives on a volume so settings/snapshots survive rebuilds
ENV DB_PATH=/data/sentinel.db
VOLUME ["/data"]

# run unprivileged
RUN useradd --create-home sentinel && mkdir -p /data \
    && chown -R sentinel:sentinel /app /data
USER sentinel

CMD ["python", "bot.py"]
