ARG BUILD_FROM=ghcr.io/home-assistant/aarch64-base-python:3.12-alpine3.21
FROM ${BUILD_FROM}

WORKDIR /opt/netgear-hack

COPY netgear_client.py netgear_client.py
COPY router_profile.example.json router_profile.example.json
COPY app.py app.py
COPY run.sh /run.sh

RUN chmod a+x /run.sh

CMD [ "/run.sh" ]
