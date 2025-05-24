
FROM python:3.10-slim

WORKDIR /app

ENV DISABLE_SCOPE_VALIDATION=true

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# Ensure src is a package (should already have __init__.py, but enforce)
RUN touch src/__init__.py

# Set PYTHONPATH so /app/src is importable
ENV PYTHONPATH="/app/src"

EXPOSE 5000

CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "--worker-class", "eventlet", "src.app:app"]
