
.PHONY: clang-toolchain

clang-toolchain:
	docker build --build-arg UID=$(shell id -u) -t pktvisor/clang-toolchain -f Dockerfile.clang-toolchain .
