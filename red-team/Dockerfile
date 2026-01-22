FROM kalilinux/kali-rolling:latest

# Update and install essential tools
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    vim \
    nano \
    netcat-traditional \
    nmap \
    nikto \
    sqlmap \
    gobuster \
    dirb \
    hydra \
    john \
    hashcat \
    burpsuite \
    zaproxy \
    python3 \
    python3-pip \
    nodejs \
    npm \
    jq \
    httpie \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install additional Python tools
RUN pip3 install --break-system-packages \
    requests \
    beautifulsoup4 \
    pyjwt \
    jwt \
    colorama

# Create working directory
WORKDIR /workspace

# Copy exercise files
COPY exercises/ /workspace/exercises/
COPY answers/ /workspace/answers/
COPY scripts/ /workspace/scripts/

# Set environment variable for target
ENV TARGET_URL="http://juice-shop:3000"

# Keep container running
CMD ["tail", "-f", "/dev/null"]
