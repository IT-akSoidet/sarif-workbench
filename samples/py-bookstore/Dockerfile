FROM python:3.9-slim

# Tools used by the (intentionally vulnerable) shell-based PDF/CSV export code.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        wkhtmltopdf \
        coreutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV FLASK_APP=app.main
ENV PYTHONUNBUFFERED=1

# Seed the database at build time so the container is ready on first boot.
RUN python -m app.db_init

EXPOSE 5050

CMD ["python", "-m", "app.main"]
