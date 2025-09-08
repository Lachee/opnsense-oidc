#!/bin/sh

NAME=oidc
CATEGORY=devel

WORK_DIR=$(pwd)
PLUGIN_DIR=/usr/plugins/$CATEGORY/$NAME

echo "Copying source..."
rm $PLUGIN_DIR
cp -r $WORK_DIR $PLUGIN_DIR

echo "Building package..."
cd $PLUGIN_DIR
make package
PKG_PATH=$(find work/pkg/*.pkg)

echo "Installing $PKG_PATH..."
pkg delete -fy *-oidc*
pkg add $(find work/pkg/*.pkg)

echo "done."