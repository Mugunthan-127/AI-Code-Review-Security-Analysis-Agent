FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install CPU-only PyTorch FIRST (avoids pulling 2GB of NVIDIA/CUDA libraries)
RUN pip install --no-cache-dir \
    torch==2.4.1+cpu \
    --extra-index-url https://download.pytorch.org/whl/cpu

# Install remaining python dependencies (sentence-transformers will reuse torch above)
COPY requirements.txt .
RUN pip install --default-timeout=1000 --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
