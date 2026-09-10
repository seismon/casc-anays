FROM python:3.11-slim

LABEL maintainer="seismon"
LABEL description="CASC-ANAYS v4.0 — Global Analytical Complex"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    git perl curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY casc_anays.py .

RUN mkdir -p reports repos

ENTRYPOINT ["python", "casc_anays.py"]
CMD ["--print-help"]
