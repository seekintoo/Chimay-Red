# -*- coding: utf-8 -*-
""" Constant defines for chimay-red exploit and utilities """

import argparse
import os

# Switches
DEBUG = False  # Not used (currently)
VERBOSE = False  # Not used  (currently)
PROFILING = False

# Architectures
ARCHS = ("x86", "mipsbe", "smips", "mmips", "arm", "powerpc", "tile")
SUPPORTED_ARCHS = (ARCHS[0], ARCHS[1])

# Filenames and filepaths
CWD = os.getcwd()
BASE_STORAGE_PATH = os.path.join(CWD, "storage")

ROS_NPK_FMT = "routeros-{}-{}.npk"
ROS_NPK_SHA256_FMT = ROS_NPK_FMT + ".sha256"

WWW_BIN_FMT = "www-{}-{}.bin"
WWW_BIN_SHA256_FMT = WWW_BIN_FMT + ".sha256"

# cProfiles (files to trace)
TRACEFILES = (
    os.path.join(CWD, "mikrodb.py"),
    os.path.join(CWD, "lib", "utils.py"),
    os.path.join(CWD, "lib", "versions.py")
)

# URLS
MK_DOWNLOAD_PAGE = "https://mikrotik.com/download"
MK_DOWNLOAD_CDN = "https://download2.mikrotik.com/routeros"

# Offsets and Lenghts
MAGIC_SIZE = 0x4
SQUASHFS_OFFSET = 0x1000
SQUASHFS_TILE_OFFSET = 0x10000

SQUASHFS_MAGIC = b'hsqs'

PTHREAD_STACK_SIZE = 0x20000
PTHREAD_DEFAULT_STACK_SIZE = 0x800000  # http://man7.org/linux/man-pages/man3/pthread_create.3.html

# Types
NativeTextFactory = str

# Namespaces
TARGET = argparse.Namespace()

# Ports
PORTS = {
    "FTP_PORT": 21,
    "SSH_PORT": 22,
    "TELNET_PORT": 23,
    "HTTP_PORT": (80, 8080),
    "DEBUG_TELNET_PORT": 23000
}

# Vectors (techniques)
VECTORS = (
    "mikrodb",
    "build",
    "leak",
    "default"
)
