FROM golang as builder
RUN mkdir -p $GOPATH/src/github.com/ns1/pktvisor
COPY ./* $GOPATH/src/github.com/ns1/pktvisor/
RUN rm -rf $GOPATH/src/github.com/ns1/pktvisor/pktvisor
WORKDIR $GOPATH/src/github.com/ns1/pktvisor
RUN go get
RUN go build -v -a -installsuffix cgo -ldflags="-w -s" -o /go/bin/pktvisor_exporter

# --------------------------------------------------------------------------------

FROM ubuntu:18.04
COPY --from=builder /go/bin/pktvisor_exporter /usr/bin/pktvisor_exporter

EXPOSE 9998

ENTRYPOINT [ "/usr/bin/pktvisor_exporter" ]
