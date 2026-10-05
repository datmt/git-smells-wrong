BINARY := git-smells-wrong
BUILD_DIR := bin
IMAGE := ghcr.io/yourorg/git-smells-wrong:latest
VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo dev)

.PHONY: all build test vet clean docker docker-run docker-push release lint

all: build

build:
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build -trimpath -ldflags="-w -s -X main.version=$(VERSION)" -o $(BUILD_DIR)/$(BINARY) ./cmd/git-smells-wrong

release:
	./release.sh $(VERSION)

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -rf $(BUILD_DIR)

docker:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE) .

docker-push:
	./docker-build-push.sh $(VERSION)

docker-run:
	docker run --rm $(IMAGE) --help
