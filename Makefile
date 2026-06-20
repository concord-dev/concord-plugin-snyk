BIN := bin/concord-plugin-snyk
VERSION ?= v0.1.0
INSTALL_DIR := $(HOME)/.concord/plugins/snyk/$(VERSION)

.PHONY: build install clean

build:
	go build -o $(BIN) ./cmd/concord-plugin-snyk

install: build
	mkdir -p $(INSTALL_DIR)
	cp $(BIN) $(INSTALL_DIR)/concord-plugin-snyk

clean:
	rm -rf bin
