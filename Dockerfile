
FROM python:3.13-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git g++ make pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN git clone --depth 1 https://github.com/zhlynn/zsign.git /tmp/zsign \
    && cd /tmp/zsign/build/linux \
    && make clean && make \
    && ZSIGN_PATH="$(find /tmp/zsign -type f -name zsign -perm -111 -print -quit)" \
    && test -n "$ZSIGN_PATH" \
    && install -m 755 "$ZSIGN_PATH" /usr/local/bin/zsign \
    && rm -rf /tmp/zsign

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY bot.py ./bot.py

CMD ["python", "bot.py"]
