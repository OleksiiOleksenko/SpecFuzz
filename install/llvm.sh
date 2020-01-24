#!/usr/bin/env bash

echo "Installing LLVM..."
if [ -z ${INSTALL_DIR} ] ; then echo "Env. variable INSTALL_DIR must be set!" ; exit 1; fi
# shellcheck source=common.sh
source "$(dirname "$0")"/common.sh

# == Defaults ==
NAME=${NAME:-"llvm"}
VERSION=${VERSION:-"7.0.1"}
CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE:-"Debug"}

# ============
# LLVM
# ============
WORK_DIR="${INSTALL_DIR}/${NAME}-${VERSION}"
SRC_DIR="${WORK_DIR}/src"
BUILD_DIR="${WORK_DIR}/build"

mkdir -p ${WORK_DIR}

# download
download_and_untar http://llvm.org/releases/${VERSION}/llvm-${VERSION}.src.tar.xz ${SRC_DIR} 1

# configure
mkdir -p ${BUILD_DIR}
cd ${BUILD_DIR} || exit
cmake -G "Unix Makefiles" -DBUILD_SHARED_LIBS=ON -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -DLLVM_TARGETS_TO_BUILD="X86" -DCMAKE_INSTALL_PREFIX=${BUILD_DIR} ../src

# install
make -j8
make -j8 install

# ============
# CLang
# ============
CLANG_DIR="${SRC_DIR}/tools/cfe-${VERSION}.src"
RT_DIR="${SRC_DIR}/tools/compiler-rt-${VERSION}.src"

# download
download_and_untar http://llvm.org/releases/${VERSION}/cfe-${VERSION}.src.tar.xz ${CLANG_DIR} 1
download_and_untar http://llvm.org/releases/${VERSION}/compiler-rt-${VERSION}.src.tar.xz ${RT_DIR} 1

# configure
mkdir -p ${BUILD_DIR}
cd ${BUILD_DIR} || exit
cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -DLLVM_TARGETS_TO_BUILD="X86" -DCMAKE_INSTALL_PREFIX=${BUILD_DIR} ../src

# install
make -j8
make -j8 install
ln -sf ${BUILD_DIR}/bin/clang /usr/bin/clang
ln -sf ${BUILD_DIR}/bin/clang++ /usr/bin/clang++

# make the LLVM installation directory discoverable
ln -sf ${BUILD_DIR}/bin/llvm-config /usr/bin/${NAME}-${VERSION}-config

echo "LLVM installed"
