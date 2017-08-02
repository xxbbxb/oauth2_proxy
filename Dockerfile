FROM golang
ADD . /go/src/github.com/skbkontur/oauth2_proxy
WORKDIR /go/src/github.com/skbkontur/oauth2_proxy
RUN go get -u github.com/kardianos/govendor
RUN govendor sync
RUN go install github.com/skbkontur/oauth2_proxy
ENTRYPOINT ["/go/bin/oauth2_proxy"]
CMD []
EXPOSE 6601