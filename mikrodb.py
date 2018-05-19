#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" generator and helper for harvesting offsets from mass quantities
    of MikroTik www binaries accross all versions and architectures.
"""
import argparse
import os
import pickle
import sqlite3
import warnings
from collections.abc import MutableMapping
from hashlib import sha256

from lib import defines
from lib.rop import MikroROP
from lib.thirdparty.PySquashfsImage import SquashFsImage
from lib.utils import check_squashfs_offset, find_files, write_to_file, print_progress
from lib.versions import dump_available_versions, yield_ros_images


class PrintHelpException(Exception):
    def __init__(self, exception):
        super().__init__(exception)
        warnings.warn(str(exception))
        raise SystemExit(PARSER.print_help())


class MikroBase(object):
    def __init__(self, *args, **kw):
        self._protocol = kw.get("protocol", pickle.HIGHEST_PROTOCOL)

    def dumps(self, value):
        """Serializes object `value`."""
        # serialize anything but ASCII strings
        return pickle.dumps(value, protocol=self._protocol)

    @staticmethod
    def loads(value):
        """Deserializes object `value`."""
        return pickle.loads(value)


# TODO: change table name to mikrodb from legacy name
class MikroDb(MutableMapping, MikroBase):
    """Model mapping for sqlite3 database"""

    def __init__(self, engine, **kw):
        super(MikroDb, self).__init__(engine, **kw)

        if not isinstance(engine, str):
            raise TypeError("engine URI expecting type str, got {0}".format(type(engine)))
        elif engine.startswith("lite://"):
            self._engine = engine.split("://")[1]
        else:
            self._engine = engine

        self._store = sqlite3.connect(self._engine)
        self._store.text_factory = defines.NativeTextFactory

        self._cursor = self._store.cursor()
        self._cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS wwwdb (
                key TEXT PRIMARY KEY NOT NULL,
                value TEXT NOT NULL
            )
            """
        )
        self._store.commit()

    def __getitem__(self, key):
        self._cursor.execute(
            'SELECT value FROM wwwdb WHERE key=?', (self.dumps(key),))
        row = self._cursor.fetchone()
        if row:
            return self.loads(row[0])
        else:
            raise KeyError(key)

    def __setitem__(self, k, v):
        self._cursor.execute(
            'INSERT OR REPLACE INTO wwwdb VALUES (?, ?)',
            (self.dumps(k), self.dumps(v))
        )
        self._store.commit()

    def __delitem__(self, key):
        self._cursor.execute(
            'DELETE FROM wwwdb WHERE key=?', (self.dumps(key),))
        self._store.commit()

    def __iter__(self):
        for row in self._store.execute('SELECT key FROM wwwdb'):
            yield self.loads(row[0])

    def __len__(self):
        return int(self._store.execute('SELECT COUNT(*) FROM wwwdb').fetchone()[0])

    def update_nested_key(self, root_key: str, sub_key: str, data: '*') -> bool:
        """

        :param root_key:
        :param sub_key:
        :param data:
        :return:
        """
        if not all(isinstance(var, str) for var in (root_key, sub_key)):
            raise TypeError("root_key, sub_key expecting type str, got {0},{1}".format(type(root_key), type(sub_key)))
        elif root_key not in self:
            raise IndexError("unable to locate the root key in the dictionary object!")

        current = self[root_key]

        if isinstance(data, dict) and bool(data):
            for k, v in data.items():
                current[sub_key][k] = v
        else:
            current[sub_key] = data

        self[root_key] = current

        return True


# TODO: Add local version builder for existing `storage`
class MikroDbBuilder(MikroDb):
    def __init__(self, *args, **kw):
        super(MikroDbBuilder, self).__init__(*args, **kw)

        self._verbose = kw.get("verbose", False)
        self._versions = kw.get("versions", False)
        self._architectures = kw.get("architectures", defines.ARCHS)

        self._available_versions = dict()

        if all((self._architectures, self._versions)):
            if not all(isinstance(var, (tuple, list)) for var in (self._architectures, self._versions)):
                raise TypeError("architectures, versions expecting type(s) (tuple, list), got {0},{1}".format(
                    type(self._architectures), type(self._versions)
                ))

            for architecture in self._architectures:
                self._available_versions[architecture] = self._versions

        if not os.path.exists(defines.BASE_STORAGE_PATH):
            os.makedirs(defines.BASE_STORAGE_PATH)

    @staticmethod
    def generate_base_dir(architecture: str, root: str, create_dirs=True):
        """

        :param architecture:
        :param root:
        :param create_dirs:
        :return:
        """
        base_dir = os.path.join(
            defines.BASE_STORAGE_PATH,
            root,
            architecture
        )

        if create_dirs:
            if not os.path.exists(base_dir):
                os.makedirs(base_dir)

        return base_dir

    def prepare_versions(self):
        """

        :return:
        """
        self._available_versions = dump_available_versions(
            self._architectures, verbose=self._verbose
        )

        return self._available_versions

    def populate_npk_storage(self):
        """

        :return:
        """
        if not self._available_versions:
            self.prepare_versions()

        for architecture, versions in self._available_versions.items():
            if not versions:
                continue

            version_cursor = int()
            architecture_npk_dir = self.generate_base_dir(architecture, "npk")

            for firmware in yield_ros_images(architecture, versions, verbose=self._verbose):
                filepath = os.path.join(
                    architecture_npk_dir,
                    defines.ROS_NPK_FMT.format(architecture, versions[version_cursor])
                )

                write_to_file(firmware.content, filepath)

                sha256hash = sha256(firmware.content).hexdigest()

                write_to_file("{}".format(sha256hash).encode(),
                              "{}.sha256".format(filepath))

                version_cursor += 1

        return True

    def populate_npk_table(self, tablename="npk"):
        """

        :param tablename:
        :return:
        """
        if not self._available_versions:
            self.prepare_versions()

        if tablename not in self:
            self[tablename] = dict()

        for architecture, versions in self._available_versions.items():
            if not versions:
                continue

            npk_temptable = dict()

            if architecture not in self[tablename]:
                self.update_nested_key(tablename, architecture, dict())

            for version in versions:
                for shafile in find_files(
                        defines.BASE_STORAGE_PATH,
                        defines.ROS_NPK_SHA256_FMT.format(architecture, version)
                ):
                    with open(shafile) as shafile_fd:
                        sha256hash = shafile_fd.read()
                        shafile_fd.close()

                    npk_temptable[version] = {"sha256hash": sha256hash}

            self.update_nested_key(tablename, architecture, npk_temptable)

        return True

    def populate_www_storage(self):
        """

        :return:
        """
        if not self._available_versions:
            self.prepare_versions()

        for architecture, versions in self._available_versions.items():
            if not versions:
                continue

            architecture_www_dir = self.generate_base_dir(architecture, "www")

            for version in versions:
                for firmware_path in find_files(
                        defines.BASE_STORAGE_PATH,
                        defines.ROS_NPK_FMT.format(architecture, version)
                ):
                    filepath = os.path.join(
                        architecture_www_dir,
                        defines.WWW_BIN_FMT.format(architecture, version)
                    )

                    offset = defines.SQUASHFS_OFFSET if architecture != "tile" else defines.SQUASHFS_TILE_OFFSET
                    if not check_squashfs_offset(firmware_path, offset=offset):
                        raise RuntimeWarning("Unaccounted error occured during squashfs offset validation")
                    else:
                        squashfs = SquashFsImage(firmware_path, offset=offset)

                    www_search = [
                        www_bin.getContent() for www_bin in squashfs.root.findAll()
                        if www_bin.name == b"www" and www_bin.hasAttribute(0o100000)
                    ]

                    if not www_search:
                        raise RuntimeWarning("Could not locate www binary for npk: {}".format(
                            firmware_path.split("/")[-1]))

                    write_to_file(www_search[0], filepath)

                    sha256hash = sha256(www_search[0]).hexdigest()

                    write_to_file("{}".format(sha256hash).encode(),
                                  "{}.sha256".format(filepath))

        return True

    def populate_www_table(self, tablename="www"):
        """

        :param tablename:
        :return:
        """
        if not self._available_versions:
            self.prepare_versions()

        if tablename not in self:
            self[tablename] = dict()

            for architecture, versions in self._available_versions.items():
                if not versions:
                    continue

                www_temptable = dict()

                if architecture not in self[tablename]:
                    self.update_nested_key(tablename, architecture, dict())

                for version in versions:
                    for shafile in find_files(
                            defines.BASE_STORAGE_PATH,
                            defines.WWW_BIN_SHA256_FMT.format(architecture, version)
                    ):
                        with open(shafile) as shafile_fd:
                            sha256hash = shafile_fd.read()
                            shafile_fd.close()

                        www_temptable[version] = {"sha256hash": sha256hash}

                self.update_nested_key(tablename, architecture, www_temptable)

        return True

    def populate_www_offsets(self, tablename="www"):
        """

        :param tablename:
        :return:
        """
        for architecture, versions in self._available_versions.items():
            if "x86" not in architecture:  # LOCK to x86 for now
                print("Skipping architecture {0} because this version works with x86 only currently".format(
                    architecture))
            else:
                temp_table = self["www"][architecture]

            with print_progress("Generating offsets for version") as progress:
                for version in versions:
                    progress.status(version)
                    for firmware_path in find_files(
                            defines.BASE_STORAGE_PATH,
                            defines.WWW_BIN_FMT.format(architecture, version)
                    ):
                        ropper = MikroROP(firmware_path)
                        temp_table[version]["offsets"] = ropper.offsets._asdict()

                progress.success()
                self.update_nested_key(tablename, architecture, temp_table)

        return True

    def generate_database(self, **kw):
        """

        :param kw:
        :return:
        """
        generate_npk = kw.get("generate_npk", True)
        generate_www = kw.get("generate_www", True)
        generate_offsets = kw.get("generate_offsets", True)

        if generate_npk:
            self.populate_npk_storage()
            self.populate_npk_table()
        if generate_www:
            self.populate_www_storage()
            self.populate_www_table()
        if generate_offsets:
            self.populate_www_offsets()

        return True


def main(verbose=False, architectures=None, versions=None):
    """ mikrodb.py entrypoint """
    if architectures is None:
        architectures = defines.SUPPORTED_ARCHS

    engine = "lite://mikro.db"
    builder = MikroDbBuilder(
        engine,
        verbose=verbose,
        versions=versions,
        architectures=architectures)

    return builder.generate_database()


if __name__ == "__main__":
    PARSER = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\n
Example: 
    ./mikrodb.py --architectures="x86" --versions="6.36.4,6.38.4"
""")

    PARSER.add_argument("-v", "--verbose",
                        action="store_true",
                        default=0,
                        help="Verbosity mode")

    PARSER.add_argument("--architectures",
                        action="store",
                        required=False,
                        help='architectures to build for. Eg. --architectures="x86" or "x86,mmips"')

    PARSER.add_argument("--versions",
                        action="store",
                        required=False,
                        help='versions to build for. Eg. --versions="6.38.4" or "6.36.4,6.38.4"')
    ARGS = PARSER.parse_args()

    is_verbose = True if ARGS.verbose else False

    try:
        if not ARGS.architectures:
            ARGS.architectures = defines.SUPPORTED_ARCHS[0]
            raise RuntimeError("No architecture specified, defaulting to ({})".format(defines.SUPPORTED_ARCHS[0]))

        architectures = list()
        for architecture in ARGS.architectures.split(","):
            if architecture not in defines.SUPPORTED_ARCHS:
                raise RuntimeError("Unsupported architecture specified: {0}".format(architecture))
            else:
                architectures.append(architecture)

        versions = list()
        if ARGS.versions:
            for version in ARGS.versions.split(","):
                if int(version.split(".")[0]) < 6:
                    raise RuntimeError("version cannot be outside of the 6.x range")
                else:
                    versions.append(version)
    except RuntimeError as exc:
        raise PrintHelpException(exc)
    else:
        raise SystemExit(main(verbose=is_verbose, architectures=architectures, versions=versions))
