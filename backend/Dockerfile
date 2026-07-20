FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    default-jdk \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Download SpotBugs, PMD, and Checkstyle
RUN mkdir -p /opt/tools && \
    wget -qO- https://github.com/spotbugs/spotbugs/releases/download/4.8.3/spotbugs-4.8.3.tgz | tar xvz -C /opt/tools && \
    wget -qO /tmp/pmd.zip https://github.com/pmd/pmd/releases/download/pmd_releases%2F7.0.0/pmd-dist-7.0.0-bin.zip && \
    unzip -q /tmp/pmd.zip -d /opt/tools && \
    wget -qO /opt/tools/checkstyle.jar https://github.com/checkstyle/checkstyle/releases/download/checkstyle-10.13.0/checkstyle-10.13.0-all.jar && \
    wget -qO /opt/tools/findsecbugs-plugin.jar https://repo1.maven.org/maven2/com/h3xstream/findsecbugs/findsecbugs-plugin/1.12.0/findsecbugs-plugin-1.12.0.jar && \
    rm /tmp/pmd.zip && \
    chmod +x /opt/tools/spotbugs-4.8.3/bin/spotbugs /opt/tools/pmd-bin-7.0.0/bin/pmd

ENV SPOTBUGS_HOME=/opt/tools/spotbugs-4.8.3
ENV PMD_HOME=/opt/tools/pmd-bin-7.0.0
ENV CHECKSTYLE_JAR=/opt/tools/checkstyle.jar
ENV FINDSECBUGS_PLUGIN=/opt/tools/findsecbugs-plugin.jar

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
