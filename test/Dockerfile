FROM golang:latest

WORKDIR /app

COPY go.mod .
COPY go.sum .
COPY fixture.go .

RUN go build -o main .

EXPOSE 80

CMD ["./main"]
