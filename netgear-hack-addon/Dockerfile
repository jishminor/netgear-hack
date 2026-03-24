ARG BUILD_FROM=ghcr.io/home-assistant/aarch64-base:latest
FROM ${BUILD_FROM}

WORKDIR /opt/netgear-hack

COPY netgear_client.py netgear_client.py
COPY router_profile.example.json router_profile.example.json
COPY app.py app.py
COPY run.sh /run.sh

RUN apk add --no-cache python3 \
    && chmod a+x /run.sh

CMD [ "/run.sh" ]
