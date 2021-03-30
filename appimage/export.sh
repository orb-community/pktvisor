#!/bin/bash

##
# Try to extract files from docker image as atomically as possible
#

FILES=(pktvisor-x86_64.AppImage)

die () {
	echo "$@" >&2
	exit 1
}

# pass in image id as $1
main () {
	[[ $1 ]] || die "image name not specified"
	
	# make a trap that see the var
	id=
	cleanup() {
		docker rm -v "$id"
	}

	trap cleanup EXIT

	# make it
	id=$(docker create $1)
	[[ $? == 0 ]] || die "failed to create container for export"
	
	# take it
	for file in "${FILES[@]}" ; do
		docker cp "$id:$file" .
	done
}

main "$1"