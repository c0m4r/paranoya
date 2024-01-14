#!/usr/bin/env bash
set -e

###########################################################################
#                                                                         #
# Loki (daemonized) chroot script                                         #
# https://github.com/c0m4r/Loki-daemonized                                #
#                                                                         #
# Loki (daemonized): Simple IOC and YARA Scanner                          #
# Copyright (c) 2015-2023 Florian Roth                                    #
# Copyright (c) 2023-2024 c0m4r                                           #
#                                                                         #
# This program is free software: you can redistribute it and/or modify    #
# it under the terms of the GNU General Public License as published by    #
# the Free Software Foundation, either version 3 of the License, or       #
# (at your option) any later version.                                     #
#                                                                         #
# This program is distributed in the hope that it will be useful,         #
# but WITHOUT ANY WARRANTY; without even the implied warranty of          #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
# GNU General Public License for more details.                            #
#                                                                         #
# You should have received a copy of the GNU General Public License       #
# along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                         #
###########################################################################

# -----------------------------------
# Variables
# -----------------------------------

# Base OS to use as chroot environment
BASEOS=$1

# Colors
ORANGE="\e[1;33m"
ENDCOLOR="\e[0m"

# -----------------------------------
# rootfs package definitions
# -----------------------------------

# Kernel architecture
KERNEL_ARCH=$(cat /proc/sys/kernel/arch)

if [[ "$KERNEL_ARCH" == "x86_64" ]]; then
    # Alpine x86_64
    ALPINE_DLNAME="alpine-minirootfs-3.19.0-x86_64.tar.gz"
    ALPINE_ROOTFS="https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/x86_64/alpine-minirootfs-3.19.0-x86_64.tar.gz"
    ALPINE_SHA256="f2b6248c9cbcb0993744d86ca9f67a058706f4ef5bf8c3c47d1cca8acf2013e0 alpine-minirootfs-3.19.0-x86_64.tar.gz"

    # Arch x86_64
    ARCH_DLNAME="archlinux-bootstrap-x86_64.tar.gz"
    ARCH_ROOTFS="https://geo.mirror.pkgbuild.com/iso/2024.01.01/archlinux-bootstrap-x86_64.tar.gz"
    ARCH_SHA256="7f3a938bd7a5d5a85ae96b0ffcf7f432282b38d51e5dfe988f7daca677c72b65 archlinux-bootstrap-x86_64.tar.gz"

    # Void x86_64
    VOID_DLNAME="void-x86_64-ROOTFS-20230628.tar.xz"
    VOID_ROOTFS="https://repo-default.voidlinux.org/live/20230628/void-x86_64-ROOTFS-20230628.tar.xz"
    VOID_SHA256="8e20003b663bc4a9c4dbe3383e3ac94a7bcf051e47f433c63c24bd639ca19334 void-x86_64-ROOTFS-20230628.tar.xz"
elif [[ "$KERNEL_ARCH" == "aarch64" ]]; then
    # Alpine aarch64
    ALPINE_DLNAME="alpine-minirootfs-3.19.0-aarch64.tar.gz"
    ALPINE_ROOTFS="https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/aarch64/alpine-minirootfs-3.19.0-aarch64.tar.gz"
    ALPINE_SHA256="ee6d3597c078e50a837a2d124594c439957fbd9e653d1286afb355c43370d0d1 alpine-minirootfs-3.19.0-aarch64.tar.gz"

    # Void aarch64
    VOID_DLNAME="void-aarch64-ROOTFS-20230628.tar.xz"
    VOID_ROOTFS="https://repo-default.voidlinux.org/live/20230628/void-aarch64-ROOTFS-20230628.tar.xz"
    VOID_SHA256="d6d10addd669d4d458e57ea38fc73086aedf911b6d702e5b4ea97cade08cbc6f void-aarch64-ROOTFS-20230628.tar.xz"
fi

# -----------------------------------
# Functions
# -----------------------------------

# Color print function
print() {
    echo -e "${ORANGE}${1}${ENDCOLOR}"
}

# Example usage
example_usage() {
    echo "Example usage:"
    echo ""
    echo "# sudo mount -o bind /home ${1}/mnt"
    echo "# sudo chroot ${1} /bin/bash"
    echo ""
    echo "# cd opt/Loki-daemonized"
    echo "# ./loki.py --noprocscan -p /mnt"
}

# define get command
function define_get() {
    if command -v curl &> /dev/null ; then
        GET="curl -O -J"
    elif command -v wget &> /dev/null ; then
        GET="wget"
    else
        echo "Can't download, no curl or wget found."
        exit 1
    fi
}

# deploy chroot
function deploy_chroot() {
    # ------------------------------
    # Params:
    # $1 - chroot directory name
    # $2 - tarball file name
    # $3 - script name prefix
    # ------------------------------
    set -e
    if [[ ! -d ${1} ]]; then
        print "Deploing ${2} to ${1}"

        mkdir -p $1
        tar xvf "${2}" -C $1
        echo "You need root access to mount ${1}/proc and ${1}/dev"

        if [[ "${3}" == "arch" ]]; then
            cd $1
            mkdir dev proc sys
            rm -df root.x86_64/dev root.x86_64/proc root.x86_64/sys
            mv root.x86_64/* .
            rm -d root.x86_64
            cd -
            sudo mount -o bind ${1} ${1}
        fi

        sudo mount -t proc none ${1}/proc
        sudo mount -o bind /dev ${1}/dev

        trap "sudo umount -l ${1}/proc ${1}/dev ${1}" ERR EXIT

        cp /etc/resolv.conf ${1}/etc/
        cp scripts/${3}.sh ${1}/
        chmod +x ${1}/${3}.sh
        sudo chroot ${1} /${3}.sh
        print "Chroot deployed"
        example_usage "${1}"
        echo ""
        print "Cleaning mounts..."
    else
        echo "${1} already exists"
        if [[ "${1}" ]]; then
            example_use "${1}"
        else
            example_use "alpine"
        fi
    fi
}

# -----------------------------------
# Verify and deploy
# -----------------------------------

define_get

if [[ "${BASEOS}" == "alpine" ]]; then
    if [[ ! "${ALPINE_DLNAME}" ]]; then
        echo "${KERNEL_ARCH} package for ${BASEOS} unavailable" ; exit 1
    elif [[ ! -e "${ALPINE_DLNAME}" ]]; then
        ${GET} "${ALPINE_ROOTFS}"
    fi

    echo "${ALPINE_SHA256}" | sha256sum -c || rm "${ALPINE_DLNAME}"
    deploy_chroot "alpine" "${ALPINE_DLNAME}" "alpine"
elif [[ "${BASEOS}" == "arch" ]]; then
    if [[ ! "${ARCH_DLNAME}" ]]; then
        echo "${KERNEL_ARCH} package for ${BASEOS} unavailable" ; exit 1
    elif [[ ! -e "${ARCH_DLNAME}" ]]; then
        ${GET} "${ARCH_ROOTFS}"
    fi

    echo "${ARCH_SHA256}" | sha256sum -c || rm "${ARCH_DL_NAME}"
    deploy_chroot "arch/root.x86_64" "${ARCH_DLNAME}" "arch"
elif [[ "${BASEOS}" == "void" ]]; then
    if [[ ! "${VOID_DLNAME}" ]]; then
        echo "${KERNEL_ARCH} package for ${BASEOS} unavailable" ; exit 1
    elif [[ ! -e "${VOID_DLNAME}" ]]; then
        ${GET} "${VOID_ROOTFS}"
    fi

    echo "${VOID_SHA256}" | sha256sum -c || rm "${VOID_DLNAME}"
    deploy_chroot "void" "${VOID_DLNAME}" "void"
else
    echo "Choose base OS first: ./chroot.sh <alpine|arch|void>"
    exit 1
fi
