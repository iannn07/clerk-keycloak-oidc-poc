FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /clerk-bridge .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /clerk-bridge /clerk-bridge
EXPOSE 8090
ENTRYPOINT ["/clerk-bridge"]
