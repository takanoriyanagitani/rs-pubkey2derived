#!/bin/sh

port=62581
addr=127.0.0.1
docd=./target

miniserve \
	--port ${port} \
	--interfaces "${addr}" \
	"${docd}"
