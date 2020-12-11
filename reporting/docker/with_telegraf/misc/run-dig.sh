#!/usr/bin/env bash

dig @8.8.8.8 www.ns1.com
sleep 2
dig @1.1.1.1 nsone.net
sleep 2
dig @1.1.1.1 nonexistABC123.nsone.net
sleep 2
dig @dns1.p01.nsone.net nonexistABC123.nozone
sleep 2
dig @8.8.8.8 ns1.com mx
sleep 2
dig @8.8.8.8 +tcp dns1.p01.nsone.net aaaa
sleep 2

