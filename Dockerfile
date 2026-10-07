FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
COPY static ./static
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /checker .

FROM scratch
COPY --from=build /checker /checker
USER 65534:65534
EXPOSE 8080
ENTRYPOINT ["/checker"]
