#!/bin/sh

NAME=oidc
CATEGORY=devel

WORK_DIR=$(pwd)
PLUGIN_DIR=/usr/plugins/$CATEGORY/$NAME

echo "Copying sources..."
rm $PLUGIN_DIR
mkdir -p $PLUGIN_DIR
cp $WORK_DIR/Makefile $PLUGIN_DIR/Makefile
cp $WORK_DIR/pkg-descr $PLUGIN_DIR/pkg-descr
cp -r $WORK_DIR/src $PLUGIN_DIR/src

echo "Building package..."
cd $PLUGIN_DIR
make package
PKG_PATH=$(find work/pkg/*.pkg)

echo "Installing $PKG_PATH..."
pkg delete -fy os-oidc*
pkg add $(find work/pkg/*.pkg)

echo "done."