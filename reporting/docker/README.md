# docker
Here we provide an example of how to collector `pktvisord` metrics with `telegraf`

This directory contains:
- [docker compose](./docker-compose.yml)
- [telegraf config](./config/telegraf.conf)
- [docker image with pktvisord and telegraf](./with_telegraf)
- [setup script](./setup.sh)

## docker-compose
The docker-compose file has elastisearch, kibana, grafana, and 2 demo pktvisor containers forwarding to elasticsearch via an in-built telegraf

## how to:
```
# assuming you're in this folder:
docker-compose build pktvisor-pop1
docker-compose pull
docker-compose up -d
./setup.sh

# then go to localhost:3000 and login with admin:admin
```
