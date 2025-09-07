#!/bin/sh

cp -r . /usr/plugins/net-mgmt/os-oidc

cd /usr/plugins/net-mgmt/os-oidc
make clean package
pkg delete -fy os-oidc*
pkg add $(find work/pkg/*.pkg)