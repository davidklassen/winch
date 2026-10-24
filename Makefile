ARCH ?= arm64
IMAGE := $(HOME)/.cache/winch/debian-13-genericcloud-$(ARCH).qcow2
VMENV := WINCH_BIN=$(CURDIR)/bin/winch WINCH_VM_IMAGE=$(IMAGE) WINCH_VM_ARCH=$(ARCH)

.PHONY: build helpers tidy lint test test-integration vm-image vm

build: helpers
	go build -o bin/winch ./cmd/winch

helpers:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags=-s -o internal/helperbin/helper-linux-amd64 ./cmd/winch-helper
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags=-s -o internal/helperbin/helper-linux-arm64 ./cmd/winch-helper

tidy:
	go mod tidy
	golangci-lint fmt

lint: helpers
	golangci-lint run ./...
	golangci-lint run --build-tags integration ./test/...

test: helpers
	go test ./...

test-integration: build vm-image
	$(VMENV) go test -tags integration -count=1 -parallel 4 -timeout 30m ./test/...

vm-image: $(IMAGE)

$(IMAGE):
	mkdir -p $(dir $@)
	curl -fL -o $@.part https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-$(ARCH).qcow2
	mv $@.part $@

vm: build vm-image
	$(VMENV) go run ./internal/vmtest/vmrun
