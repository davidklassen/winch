ARCH ?= arm64
OS ?= debian-13
PARALLEL ?= 4
N ?= 1
ONLINE ?=
RUN ?=
VERBOSE ?=
TIMEOUT ?= $(if $(value RUN),10m,30m)
CACHE := $(HOME)/.cache/winch
IMAGE := $(CACHE)/$(OS)-$(ARCH).qcow2
IMAGE_URL.debian-13 := https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-$(ARCH).qcow2
IMAGE_URL.ubuntu-24.04 := https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-$(ARCH).img
IMAGE_URL.ubuntu-26.04 := https://cloud-images.ubuntu.com/resolute/current/resolute-server-cloudimg-$(ARCH).img
VMENV := WINCH_BIN=$(CURDIR)/bin/winch WINCH_VM_OS=$(OS) WINCH_VM_IMAGE=$(IMAGE) WINCH_VM_ARCH=$(ARCH) WINCH_VM_CACHE=$(CACHE) WINCH_VM_ONLINE=$(ONLINE)

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
	go test -race ./...

test-integration: build vm-image
	$(VMENV) go test $(if $(VERBOSE),-v) -count=1 -parallel $(PARALLEL) -timeout $(TIMEOUT) $(if $(value RUN),-run '$(value RUN)') ./test/...

test-repo: build vm-image
	$(VMENV) go run ./internal/vmtest/vmrun -refresh

vm-image: $(IMAGE)

$(IMAGE):
	mkdir -p $(dir $@)
	$(if $(IMAGE_URL.$(OS)),,$(error OS=$(OS): use debian-13, ubuntu-24.04, or ubuntu-26.04))
	curl -fL -o $@.part $(IMAGE_URL.$(OS))
	mv $@.part $@

vm: build vm-image
	$(VMENV) go run ./internal/vmtest/vmrun -n $(N)
