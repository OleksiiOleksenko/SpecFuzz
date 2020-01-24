#!/usr/bin/env bash

echo "Installing HonggFuzz..."
if [ -z ${INSTALL_DIR} ] ; then echo "Env. variable INSTALL_DIR must be set!" ; exit 1; fi
# shellcheck source=common.sh
source "$(dirname "$0")"/common.sh

NAME="honggfuzz"
VERSION="589a9fb92"

WORK_DIR="${INSTALL_DIR}/${NAME}-${VERSION}"  # the directory where we link the sources and build them
SRC_DIR="${WORK_DIR}/src"
BUILD_DIR="${WORK_DIR}/build"

mkdir -p ${WORK_DIR}

# download
clone_git_repo https://github.com/google/honggfuzz.git ${SRC_DIR} ${VERSION} ""

# configure
mkdir -p ${BUILD_DIR}
cd ${SRC_DIR} || exit

# install
make -j8
make -j8 install

echo "HonggFuzz is installed"
