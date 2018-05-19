# -*- coding: utf-8 -*-
"""
Pwntools GDB helper module for Chimay-Red
"""
import time

from pwn import log, remote
from pwnlib import gdb

from lib.defines import PORTS


def attach_gdb_server(host, port, binpath, breakpoints=None, prompt=True):
    gdb_cmds = list()
    if isinstance(port, str):
        if port.isdigit():
            port = int(port)

    # GDB commands to exec on startup
    if breakpoints:
        for bp in breakpoints:
            if isinstance(bp, str):
                gdb_cmds.append("break *{0}".format(bp))
            if isinstance(bp, int):
                gdb_cmds.append("break *{0}".format(hex(bp)))

    gdb_cmds.append("set disassembly-flavor intel")
    gdb_cmds.append("c")
    gdb_cmds = '\n'.join(gdb_cmds)
    gdb.attach((host, port), execute=gdb_cmds, exe=binpath)

    if prompt:
        input("[*] Press [Enter] to continue debugging: ")

    return True


def run_new_remote_gdbserver(host, port):
    gdbserver_pid = None

    log.info("Attempting to connect to remote debugging gdbserver")
    try:
        remote_telnet = remote(host, PORTS["DEBUG_TELNET_PORT"])
    except KeyboardInterrupt:
        raise SystemExit(log.warning("SIGINT received, exiting gracefully..."))
    else:
        remote_telnet.sendline("pidof gdbserver.i686"), time.sleep(1)  # Have to sleep because of polling delay
        recv_data = remote_telnet.recv_raw(2048).decode('ascii', errors="ignore")

    for line in recv_data.split("\n"):
        newline = line.strip("\n")
        if newline.isdigit():
            gdbserver_pid = newline
            break

    if gdbserver_pid:
        log.info("killing stale gdbserver...")
        remote_telnet.sendline("kill -9 {}".format(gdbserver_pid)), time.sleep(1)

    log.info("starting new remote gdbserver and attaching...")
    remote_telnet.sendline("/flash/bin/gdbserver.i686 {}:{} --attach $(pidof www) &".format(host, port)), time.sleep(1)

    return True
