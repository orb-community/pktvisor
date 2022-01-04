
.PHONY: clang-toolchain

# for developer environments (e.g. clion docker toolchain)
# note does not require/include the source base
clang-toolchain:
	docker build --build-arg UID=$(shell id -u) -t pktvisor/clang-toolchain -f Dockerfile.clang-toolchain .
