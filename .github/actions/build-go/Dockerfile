FROM golang:latest

LABEL author="Everton Haise Taques <everton.taques@encora.com>"
LABEL maintainer="NS1 Labs"
LABEL version="1.0.0"

COPY ./entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

ENTRYPOINT [ "/entrypoint.sh" ]

