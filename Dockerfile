FROM alpine:3.21
COPY redlimitador /usr/local/bin/redlimitador
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/redlimitador"]
CMD ["run", "--bind", "0.0.0.0:8080"]
