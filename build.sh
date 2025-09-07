#!/bin/sh

make clean package

pkg delete -fy os-oidc*
pkg add $(find work/pkg/*.pkg)