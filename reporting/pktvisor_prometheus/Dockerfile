FROM golang as builder

RUN GIT_TERMINAL_PROMPT=0 git clone --depth 1 -b master --single-branch https://github.com/ns1/pktvisor.git $GOPATH/src/github.com/ns1/pktvisor \
    && cd $GOPATH/src/github.com/ns1/pktvisor/reporting/pktvisor_prometheus \
    && go get \
    && go build -a -installsuffix cgo -ldflags="-w -s" -o /go/bin/pktvisor_exporter

# --------------------------------------------------------------------------------

FROM ubuntu:18.04
COPY --from=builder /go/bin/pktvisor_exporter /usr/bin/pktvisor_exporter

EXPOSE 9998

ENTRYPOINT [ "/usr/bin/pktvisor_exporter" ]
