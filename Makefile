ARCH ?= arm64
PARALLEL ?= 4
N ?= 1
ONLINE ?=
CACHE := $(HOME)/.cache/winch
IMAGE := $(CACHE)/debian-13-genericcloud-$(ARCH).qcow2
VMENV := WINCH_BIN=$(CURDIR)/bin/winch WINCH_VM_IMAGE=$(IMAGE) WINCH_VM_ARCH=$(ARCH) WINCH_VM_CACHE=$(CACHE) WINCH_VM_ONLINE=$(ONLINE)

.PHONY: build helpers tidy lint test test-integration test-repo vm-image vm

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

test: helpers
	go test ./...

test-integration: build vm-image
	$(VMENV) go test -count=1 -parallel $(PARALLEL) -timeout 30m ./test/...

test-repo: build vm-image
	$(VMENV) go run ./internal/vmtest/vmrun -refresh

vm-image: $(IMAGE)

$(IMAGE):
	mkdir -p $(dir $@)
	curl -fL -o $@.part https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-$(ARCH).qcow2
	mv $@.part $@

vm: build vm-image
	$(VMENV) go run ./internal/vmtest/vmrun -n $(N)
