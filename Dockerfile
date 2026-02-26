FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY pyloros /usr/local/bin/pyloros
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/pyloros"]
CMD ["run", "--bind", "0.0.0.0:8080"]
