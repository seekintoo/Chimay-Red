#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import urllib.request as urllib
from collections import namedtuple

from lib.defines import MK_DOWNLOAD_CDN, MK_DOWNLOAD_PAGE
from lib.utils import print_info, print_progress


def check_ros_version(architecture: str, version: str) -> bool:
    """

    :param architecture:
    :param version:
    :return:
    """

    if not all(isinstance(var, str) for var in (architecture, version)):
        raise TypeError("Expected str type for architecture and version, got {0} and {1}".format(
            type(architecture), type(version)))

    url = "{}/{}/routeros-{}-{}.npk".format(MK_DOWNLOAD_CDN, version, architecture, version)

    request = urllib.Request(url)
    request.get_method = lambda: "HEAD"

    try:
        urllib.urlopen(request)
    except IOError:
        return False

    return True


def download_ros_version(architecture: str, version: str):
    """

    :param architecture:
    :param version:
    :return:
    """

    if not all(isinstance(var, str) for var in (architecture, version)):
        raise TypeError("Expected str type for architecture and version, got {0} and {1}".format(
            type(architecture), type(version)))

    url = "{}/{}/routeros-{}-{}.npk".format(MK_DOWNLOAD_CDN, version, architecture, version)

    try:
        response = urllib.urlopen(url)
        setattr(response, "content", response.read())
    except IOError:
        return False

    return response


def yield_ros_images(architecture: str, versions: (tuple, list), verbose=False) -> iter:
    """ yields response object from `download_ros_version()` """

    if not isinstance(architecture, str):
        raise TypeError("expecting str type for architecture, got {0}".format(type(architecture)))
    if not isinstance(versions, (tuple, list)):
        raise TypeError("expecting list type for versions, got {0}".format(type(versions)))
    
    with print_progress("Downloading NPK {} image version".format(architecture)) as progress:
        for version in versions:
            if verbose:
                progress.status(version)
            yield download_ros_version(architecture, version)


def latest_ros_version() -> list:
    """

    :return:
    """

    latest_version = None
    version_regex = re.compile(r"</th><th>(\d+\.\d+|\d+\.\d+\.\d+) \(Current\)")

    response = urllib.urlopen(MK_DOWNLOAD_PAGE).read().decode()
    for line in response.split("\n"):
        match = version_regex.search(line)
        if match:
            latest_version = list(match.groups()[0].split("."))
            break

    if not latest_version:
        raise RuntimeWarning()

    return latest_version


def ros_version_ranges(latest_version: (tuple, list)) -> namedtuple:
    versions = namedtuple(
        "versions",
        [
            "current_version",
            "minimum_major",
            "maximum_major",
            "minimum_minor",
            "maximum_minor",
            "minimum_build",
            "maximum_build"
        ]
    )

    if not latest_version:
        versions.minimum_major = 6
        versions.maximum_major = 6

        versions.minimum_minor = 0
        versions.maximum_minor = 38

        versions.minimum_build = 0
        versions.maximum_build = 5
    else:
        major, minor = versions.current_version = latest_version[0:2]

        versions.minimum_major = int(major)
        versions.maximum_major = int(major)

        versions.minimum_minor = 30
        versions.maximum_minor = int(minor)

        versions.minimum_build = 1
        versions.maximum_build = 10

    return versions


def yield_ros_availability(architecture: str) -> iter:
    """

    :param architecture:
    :return:
    """

    versions = ros_version_ranges(latest_ros_version())

    for major in [versions.minimum_major]:
        for minor in range(versions.minimum_minor, versions.maximum_minor):
            if check_ros_version(architecture, "{}.{}".format(major, minor)):
                yield "{}.{}".format(major, minor)
            for build in range(versions.minimum_build, versions.maximum_build):
                if check_ros_version(architecture, "{}.{}.{}".format(major, minor, build)):
                    yield "{}.{}.{}".format(major, minor, build)


def dump_available_versions(architectures: (tuple, list), verbose=True) -> dict:
    if not isinstance(architectures, (tuple, list)):
        raise TypeError("architectures requires tuple/list, got {0}".format(type(architectures)))

    available_versions = dict()
    available_versions_counter = int()

    if verbose:
        print_info("Testing versions for architectures: {}".format(architectures))

    for architecture in architectures:
        if verbose:
            progress = (print_progress("Testing versions for {}".format(architecture)))

        available_versions[architecture] = list()
        for version in yield_ros_availability(architecture):
            available_versions[architecture].append(version)
            if verbose:
                progress.status(version)

        architecture_versions = len(available_versions[architecture])
        available_versions_counter += architecture_versions
        if verbose:
            progress.success("\033[92m[DONE] [{}]\x1b[0m\n".format(architecture_versions))

    if verbose:
        print()
        print_info("VERSION ENUM RESULTS:")
        print()
        for architecture, versions in available_versions.items():
            print_info("Architecture [{}] results:".format(architecture))
            for version1, version2, version3 in zip(versions[::3], versions[1::3], versions[2::3]):
                print_info('{0:<10}{1:<10}{2:<}'.format(version1, version2, version3))
        print()
        print_info("Total versions found accross tested architectures: [{}]".format(available_versions_counter))

    return available_versions
