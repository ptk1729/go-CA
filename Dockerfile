FROM registry.scontain.com/sconecuratedimages/crosscompilers AS builder
COPY go-ca-gen /go-ca-gen
RUN chmod +x /go-ca-gen

# FROM registry.scontain.com/sconecuratedimages/debian
# COPY --from=builder /go-ca-gen /go-ca-gen
ENTRYPOINT ["/go-ca-gen"]
