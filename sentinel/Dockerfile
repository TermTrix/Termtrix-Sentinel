FROM python:3.12-slim

WORKDIR /app

# COPY requirements.txt /app/requirements.txt

# RUN pip install --no-cache-dir -r requirements.txt


COPY pyproject.toml .

RUN pip install -e .

# Copy shared common package
COPY termtrix_common ./termtrix_common

# Install shared package
RUN pip install --no-cache-dir -e ./termtrix_common

COPY . .

CMD ["uvicorn", "sentinel.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
