# in dev mode we just use the latest image
ifneq ($(strip $(DEV_MODE)),)
DEV_MODE := <(echo "FROM ns1labs/pktvisor:latest") appimage/Dockerfile.part
endif

BUILD_FILES := docker/Dockerfile appimage/Dockerfile.part

pktvisor-x86_64.AppImage: SHELL:=/bin/bash
pktvisor-x86_64.AppImage:
	ID=$$(cd .. && cat $(if $(DEV_MODE),$(DEV_MODE),$(BUILD_FILES)) | docker build -q -f- .) ; \
	bash export.sh $$ID

.PHONEY: clean
clean:
	rm pktvisor-x86_64.AppImage