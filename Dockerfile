FROM golang as build
ARG LCVPN_VERSION=master
RUN cd $GOPATH/src && \
git clone https://github.com/kanocz/lcvpn.git -b $LCVPN_VERSION && \
cd lcvpn && \
go get && \
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build && \
mkdir /app &&  \
cp $GOPATH/bin/* /app
VOLUME /app

FROM alpine
WORKDIR /app
COPY --from=build /app/ ./
VOLUME /config
RUN  mkdir /lib64 && ln -s /lib/libc.musl-x86_64.so.1 /lib64/ld-linux-x86-64.so.2
CMD /app/lcvpn -config /config/lcvpn.conf
