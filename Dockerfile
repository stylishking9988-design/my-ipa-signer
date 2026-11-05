
FROM python:3.13-slim

RUN apt-get update && apt-get install -y \
    git g++ make pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN git clone --depth 1 https://github.com/zhlynn/zsign.git /tmp/zsign \
    && make -C /tmp/zsign/build/linux -j2 \
    && install -m 755 /tmp/zsign/bin/zsign /usr/local/bin/zsign \
    && rm -rf /tmp/zsign

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY bot.py .

CMD ["python", "bot.py"]
