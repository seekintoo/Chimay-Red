# -*- coding: utf-8 -*-
""" General utilities file for exploits and mikrodb """
import fnmatch
import ipaddress
import linecache
import os
import socket
import struct
import tracemalloc
from binascii import hexlify

from pwn import remote, log

from lib.defines import MAGIC_SIZE, SQUASHFS_MAGIC, SQUASHFS_OFFSET

print_info = log.info
print_progress = log.progress


def craft_post_header(length=0, content_length=True):
    """ returns header with 'content-length' set to 'num' """

    if content_length:
        header = b"POST /jsproxy HTTP/1.1\r\nContent-Length: "
        header += "{}\r\n\r\n".format(str(length)).encode()
    else:
        header = b"POST /jsproxy HTTP/1.1\r\n\r\n"

    return header


def create_socket(host: str, port: int):
    """
    returns pwn.remote socket connection given:
         hostname and port number
    """
    if isinstance(port, str):
        if port.isdigit():
            port = int(port)

    try:
        s = socket.socket()
        s.connect((host, port))
        s = remote.fromsocket(s)
    except Exception:
        raise ConnectionAbortedError

    return s


def get_system_routes() -> iter:
    """Read the default gateway directly from /proc."""
    with open("/proc/net/route") as fh:
        for line in fh:
            fields = line.strip().split()
            if fields[1] == "00000000" or fields[1][0].isupper():
                continue
            yield socket.inet_ntoa(struct.pack("=L", int(fields[1], 16)))


def check_cidr_overlap(address1: str, address2: str) -> bool:
    """

    :param address1:
    :param address2:
    :return:
    """

    return ipaddress.ip_address(address1) in ipaddress.ip_network(address2)


def read_bin_file(filename: str):
    """ reads binary data from  `filename`"""
    if not os.path.isfile(filename):
        raise FileNotFoundError()

    with open(filename, "rb") as fd:
        return fd.read()


def find_files(directory: str, pattern: str):
    """

    :param directory:
    :param pattern:
    :return:
    """
    for root, _, files in os.walk(directory):
        for basename in files:
            if fnmatch.fnmatch(basename, pattern):
                filename = os.path.join(root, basename)
                yield filename


def write_to_file(data: bytes, filepath: str) -> int:
    """ Writes arbitrary bytes to a file given `data` and `filepath`

        Returns number of `bytes` written
    """

    if not isinstance(data, bytes):
        raise TypeError("data expecting type bytes, got {0}".format(type(data)))
    if not isinstance(filepath, str):
        raise TypeError("data expecting type bytes, got {0}".format(type(data)))

    with open(filepath, "wb") as fd:
        return fd.write(data)


def check_squashfs_offset(filepath: str, offset=SQUASHFS_OFFSET) -> bool:
    """

    :param filepath:
    :param offset:
    :return:
    """
    if not os.path.isfile(filepath):
        raise FileNotFoundError()

    with open(filepath, "rb") as fd:
        fd.seek(offset)
        magic_header = fd.read(MAGIC_SIZE)

    if magic_header != SQUASHFS_MAGIC:
        return False

    return True


def display_top(snapshot, key_type='lineno', limit=10, modpaths=None):
    """

    :param snapshot:
    :param key_type:
    :param limit:
    :param modpaths:
    :return:
    """
    if isinstance(modpaths, (tuple, list)):
        filter_list = list()
        for path in modpaths:
            filter_list.append(tracemalloc.Filter(True, path))
        snapshot = snapshot.filter_traces(filter_list)
    else:
        snapshot = snapshot.filter_traces((
            tracemalloc.Filter(False, "<frozen importlib._bootstrap>"),
            tracemalloc.Filter(False, "<frozen importlib._bootstrap_external>"),
            tracemalloc.Filter(False, "<unknown>"),
        ))
    top_stats = snapshot.statistics(key_type)

    print("Top {} lines".format(limit))
    for index, stat in enumerate(top_stats[:limit], 1):
        frame = stat.traceback[0]
        # replace "/path/to/module/file.py" with "module/file.py"
        filename = "/".join(frame.filename.split("/")[-2:])
        print("#%s: %s:%s: %.1f KiB" % (index, filename, frame.lineno, stat.size / 1024))
        line = linecache.getline(frame.filename, frame.lineno).strip()
        if line:
            print('    {}'.format(line))

    other = top_stats[limit:]
    if other:
        size = sum(stat.size for stat in other)
        print("%s other: %.1f KiB" % (len(other), size / 1024))
    total = sum(stat.size for stat in top_stats)
    print("Total allocated size: %.1f KiB" % (total / 1024))


def parse_mndp(data):
    """

    :param data:
    :return:
    """
    entry = dict()
    names = ('version', 'ttl', 'checksum')
    for idx, val in enumerate(struct.unpack_from('!BBH', data)):
        entry[names[idx]] = val

    pos = 4
    while pos + 4 < len(data):
        msgid, length = struct.unpack_from('!HH', data, pos)
        pos += 4

        # MAC
        if msgid == 1:
            (mac,) = struct.unpack_from('6s', data, pos)
            entry['mac'] = "%02x:%02x:%02x:%02x:%02x:%02x" % tuple(x for x in mac)

        # Identity
        elif msgid == 5:
            entry['id'] = data[pos:pos + length]

        # Platform
        elif msgid == 8:
            entry['platform'] = data[pos:pos + length]

        # Version
        elif msgid == 7:
            entry['version'] = data[pos:pos + length]

        # uptime?
        elif msgid == 10:
            (uptime,) = struct.unpack_from('<I', data, pos)
            entry['uptime'] = uptime

        # hardware
        elif msgid == 12:
            entry['hardware'] = data[pos:pos + length]

        # softid
        elif msgid == 11:
            entry['softid'] = data[pos:pos + length]

        # ifname
        elif msgid == 16:
            entry['ifname'] = data[pos:pos + length]

        else:
            entry['unknown-%d' % msgid] = hexlify(data[pos:pos + length])

        pos += length

    return entry


def mndp_scan():
    """

    :return:
    """
    cs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    cs.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    cs.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    cs.bind(('', 5678))

    cs.sendto(b'\0\0\0\0', ('255.255.255.255', 5678))

    try:
        entries = {}
        while True:
            (data, src_addr) = cs.recvfrom(1500)
            # ignore the msg we getourselves or if bad
            if data == b'\0\0\0\0' or len(data) < 18:
                continue
            else:
                entry = parse_mndp(data)

            if not entries.get(entry['mac']):
                yield {src_addr[0]: entry}
    finally:
        cs.close()
