#!/usr/bin/env bash

dig @8.8.8.8 ns1.com
sleep 3
dig @1.1.1.1 nsone.net
sleep 3
