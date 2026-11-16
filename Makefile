BINARY := dispatch

.PHONY: tidy build run clean

tidy:
	go mod tidy

build:
	go build -o $(BINARY) .

run: build
	mkdir -p devdata
	./$(BINARY) config.json

clean:
	rm -f $(BINARY)
