#!/usr/bin/env bash

# == Prepare a safe scripting environment ==
set -euo pipefail
IFS=$'\n\t'

# == Define common functions ==
function required_str {
    if [ -z $1 ]; then
        echo "The string argument is empty!"
        exit 1
    fi
}

# Download a tar archive from URL $1
# and unpack it to $2
# Set $3 to 1 to skip the uppermost directory of the archive. Otherwise, set to 0 or skip
function download_and_untar {
    local url=$1 ;
    if [ -z ${url} ]; then
        echo "The string argument is empty!"
        exit 1
    fi
    local unpack_path=$2 ;
    if [ -z ${unpack_path} ]; then
        echo "The string argument is empty!"
        exit 1
    fi
    local strip=${3:-0} ;

    if [ -d ${unpack_path} ] && [ -n "$(ls -A ${unpack_path})" ]; then
        echo "The directory ${unpack_path} already exist."
        while true; do
            read -rp "Do you wish to reinstall ${unpack_path} [Yn]?" yn
            case $yn in
                [Yy]* ) rm -rf ${unpack_path}; break;;
                [Nn]* ) echo "Skip"; return;;
                * ) echo "Please answer 'y' or 'n'.";;
            esac
        done
    fi

    wget -N -O tmp.tar ${url}
    mkdir -p ${unpack_path}
    tar xf tmp.tar -C ${unpack_path} --strip-components=${strip}
    rm tmp.tar
}

# Clone a git repo from URL $1
# to directory $2
# Optionally, checkout $3
# Optionally, apply path $4
function clone_git_repo {
    local url=$1 ; required_str ${url}
    local path=$2 ; required_str ${path}
    local checkout=$3
    local applypatch=$4

    if [ -d ${path} ] && [ -n "$(ls -A ${path})" ]; then
        echo "The directory ${path} already exist."
        while true; do
            read -rp "Do you wish to reinstall ${path} [Yn]?" yn
            case $yn in
                [Yy]* ) rm -rf ${path}; break;;
                [Nn]* ) echo "Skip"; return;;
                * ) echo "Please answer 'y' or 'n'.";;
            esac
        done
    fi

    set +e
    git clone ${url} ${path}
    set -e

    pushd ${path}
    if [ -n "${checkout}" ]; then
        git checkout ${checkout}
    fi
    if [ -n "${applypatch}" ]; then
        git apply ${applypatch}
    fi
    popd
}
