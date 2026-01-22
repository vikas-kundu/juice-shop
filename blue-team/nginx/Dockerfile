FROM nginx:alpine

# Remove default symlinks and create actual log files
RUN rm -f /var/log/nginx/access.log /var/log/nginx/error.log && \
    touch /var/log/nginx/access.log /var/log/nginx/error.log /var/log/nginx/security.log && \
    chmod 644 /var/log/nginx/*.log
