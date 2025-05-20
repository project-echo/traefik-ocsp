FROM golang:latest

WORKDIR /app

COPY go.mod .
COPY go.sum .
COPY pki/ /app/pki/
COPY fixture.go .

RUN go build -o main .

EXPOSE 8089

CMD ["./main"]
