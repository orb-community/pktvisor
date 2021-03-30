# in dev mode we just use the latest image as the start point
ifneq ($(strip $(DEV_MODE)),)
DOCKERFILE_HEAD = <(echo "FROM ns1labs/pktvisor:latest")
else
DOCKERFILE_HEAD = docker/Dockerfile
endif

pktvisor-x86_64.AppImage: SHELL:=/bin/bash #needed for the fd when DOCKERFILE_HEAD is in DEV_MODE
pktvisor-x86_64.AppImage:
	ID=$$(cd .. && cat $(DOCKERFILE_HEAD) appimage/Dockerfile.part | docker build -q -f- .) ; \
	bash export.sh $$ID

.PHONEY: clean
clean:
	rm pktvisor-x86_64.AppImage