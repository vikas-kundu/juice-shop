FROM alpine:latest

# Install OpenSSH and bash
RUN apk add --no-cache openssh bash grep gawk coreutils shadow

# Configure SSH
RUN ssh-keygen -A && \
    echo "PermitRootLogin yes" >> /etc/ssh/sshd_config && \
    echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config && \
    echo "Port 22" >> /etc/ssh/sshd_config

# Create blueteam user with password 'defend123'
RUN adduser -D -s /bin/bash blueteam && \
    echo "blueteam:defend123" | chpasswd

# Create logs directory
RUN mkdir -p /var/log/nginx && \
    chown -R blueteam:blueteam /var/log/nginx

# Create helper scripts directory
RUN mkdir -p /home/blueteam/scripts && \
    chown -R blueteam:blueteam /home/blueteam/scripts

EXPOSE 22

# Start SSH daemon
CMD ["/usr/sbin/sshd", "-D", "-e"]
