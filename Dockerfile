# Use Ubuntu 20.04 to avoid asm/types.h issue
FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt update && apt install -y \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-$(uname -r) \
    build-essential \
    python3 \
    python3-pip \
    git \
    htop \
    iproute2 \
    sudo \
    hping3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -ms /bin/bash bpfuser
USER bpfuser
WORKDIR /home/bpfuser

# Copy repo files
COPY --chown=bpfuser:bpfuser . /home/bpfuser/ddos-mitigation
WORKDIR /home/bpfuser/ddos-mitigation

# Python virtual environment
RUN python3 -m venv venv
RUN /home/bpfuser/ddos-mitigation/venv/bin/pip install --upgrade pip
RUN /home/bpfuser/ddos-mitigation/venv/bin/pip install -r requirements.txt

CMD ["/bin/bash"]
