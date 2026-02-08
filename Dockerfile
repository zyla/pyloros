FROM alpine:3.21
COPY pyloros /usr/local/bin/pyloros
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/pyloros"]
CMD ["run", "--bind", "0.0.0.0:8080"]
