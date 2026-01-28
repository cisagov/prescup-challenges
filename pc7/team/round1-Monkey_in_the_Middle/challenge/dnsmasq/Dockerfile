FROM alpine:3.22.0

# Install dnsmasq
RUN apk add --no-cache dnsmasq

# Create config directory
RUN mkdir -p /etc/dnsmasq.d

# Provide custom dnsmasq config and hosts
COPY dnsmasq.conf /etc/dnsmasq.conf

# Run dnsmasq in foreground
CMD ["dnsmasq", "-k"]
