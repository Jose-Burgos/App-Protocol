FROM gcc:latest

WORKDIR /app

COPY . /app

RUN gcc -o ./src/server.o ./src/server.c

CMD ["./src/server.o"]
