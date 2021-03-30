#!/bin/bash

FILES=(pktvisor-x86_64.AppImage)

die () {
	echo "$@" >&2
	exit 1
}

main () {
	[[ $1 ]] || die "image name not specified"
	
	id=
	cleanup() {
		docker rm -v "$id"
	}

	trap cleanup EXIT

	id=$(docker create $1)
	[[ $? == 0 ]] || die "failed to create container for export"
	
	for file in "${FILES[@]}" ; do
		docker cp "$id:$file" .
	done
}

main "$1"