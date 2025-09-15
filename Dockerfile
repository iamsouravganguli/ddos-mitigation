FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies (no linux-headers)
RUN apt update && apt install -y \
    clang \
    llvm \
    libbpf-dev \
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

# Clone your public repo
RUN git clone https://github.com/iamsouravganguli/ddos-mitigation.git
WORKDIR /home/bpfuser/ddos-mitigation

# Python venv
RUN python3 -m venv venv
RUN /home/bpfuser/ddos-mitigation/venv/bin/pip install --upgrade pip
RUN /home/bpfuser/ddos-mitigation/venv/bin/pip install -r requirements.txt

CMD ["/bin/bash"]