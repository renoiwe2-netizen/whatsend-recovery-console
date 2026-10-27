FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    chromium chromium-sandbox xvfb x11vnc novnc \
    fonts-liberation python3 python3-aiohttp tini ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 robot
WORKDIR /opt/poc
COPY bootstrap.sh fixture.html measure.py server.py index.html client.js ./
COPY chromium-policy.json /etc/chromium/policies/managed/fixture.json
RUN chmod 755 bootstrap.sh && chown -R robot:robot /opt/poc
USER robot
ENV DISPLAY=:99 HOME=/home/robot PORT=10000
EXPOSE 10000
ENTRYPOINT ["/usr/bin/tini", "--", "/opt/poc/bootstrap.sh"]
