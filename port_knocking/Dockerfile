FROM ubuntu:22.04

WORKDIR /app

# Install SSH, knockd, iptables-legacy
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
         openssh-server knockd iptables iproute2 \
    && update-alternatives --set iptables /usr/sbin/iptables-legacy \
    && update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy \
    && rm -rf /var/lib/apt/lists/*

# Prepare sshd (protected SSH service on port 2222)
RUN mkdir -p /var/run/sshd \
    && useradd -m -s /bin/bash knockuser \
    && echo 'knockuser:KnockPass2024!' | chpasswd

# Configure sshd to listen on 2222 and allow password auth
RUN sed -i 's/^#Port 22/Port 2222/' /etc/ssh/sshd_config \
    && sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && sed -i 's/^KbdInteractiveAuthentication no/#KbdInteractiveAuthentication no/' /etc/ssh/sshd_config

# knockd config & defaults
COPY knockd.conf /etc/knockd.conf
COPY knockd.default /etc/default/knockd

# Entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 2222

CMD ["/entrypoint.sh"]
