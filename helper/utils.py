#!/usr/bin/python
"""
utils.py: This module contains several helper classes
"""

import csv
import glob
import importlib
import inspect
import itertools
import fnmatch
import logging
import logging.handlers
import os
import platform
import psutil
import re
import shutil
import stat
import string
import subprocess
import sys
import thread
import threading
import unicodecsv
import warnings
import xlrd
import xml.etree.ElementTree as ET
import zipfile

from ast import literal_eval
from datetime import datetime
from distutils import util
from generic.exceptions import AcquireResourceTimeoutError, ThreadingLockError
from helper.concurrency import FileLock, ThreadingLock
from helper.shared_drive_mounting_utils import SharedDriveMountingUtils
from json import dumps
from multiprocessing.dummy import Pool as ThreadPool
from time import time, sleep
from traceback import format_exception, format_exception_only
from xml.dom import minidom
from xml.parsers.expat import ExpatError

PLATFORM = platform.system()

try:
    from pyModbusTCP.client import ModbusClient
    if PLATFORM == 'Windows':
        import win_inet_pton
except ImportError:
    pass

if PLATFORM == 'Windows':
    try:
        import _winreg as winreg
    except ImportError:
        import winreg

__copyright__ = "2020 NXP Semiconductors. All rights reserved."


class Utils(object):
    """Class containing general utility methods."""

    def __init__(self):
        pass

    class TrialContextManager(object):
        """Custom context manager"""

        def __init__(self): pass

        def __enter__(self): pass

        def __exit__(self, *args): return True

    @staticmethod
    def get_process_status_tasklist(filter, process_details):
        """Windows TASKLIST query.
        :param filter: Filter used when compounding the TASKLIST queries [str]
        :param process_details: Process to search for in TASKLIST cmd output [str|int]
        """
        tasklist_cmdlets = {
            'running': 'TASKLIST /FI "{filter}" /FI "STATUS eq RUNNING"'.format(filter=filter),
            'not_responding': 'TASKLIST /FI "{filter}" /FI "STATUS eq NOT RESPONDING"'.format(filter=filter),
            'unknown': 'TASKLIST /FI "{filter}" /FI "STATUS eq UNKNOWN"'.format(filter=filter)
        }
        for check_status, cmd in tasklist_cmdlets.iteritems():
            _, cmd_out, _ = Utils.run_subprocess(cmd, print_stdout=False, verbose=False)

            # Checking the exit code does not help => exit code is 0 for all valid <tasklist> cmdlets
            if 'No tasks are running which match the specified criteria' in cmd_out:
                continue

            if process_details in cmd_out:
                return {"check_status": check_status, "cmd_out": cmd_out}

        return {"check_status": "no_status_info_available"}

    @staticmethod
    def get_process_status_by_id(process_id=None):
        """Get Windows process status info using Windows TASKLIST internal cmd.
        The method can check for PID a process.
        Possible states reported by TASKLIST: <RUNNING | NOT RESPONDING | UNKNOWN>
        :param process_id: PID of the process [int]
        """
        filter_token = 'PID eq {process_id}'.format(process_id=process_id)
        return Utils.get_process_status_tasklist(filter_token, process_id)

    @staticmethod
    def get_process_status_by_name(process_name=None):
        """Get Windows process status info using Windows TASKLIST internal cmd.
        The method can check for a IMAGENAME of a process.
        Possible states reported by TASKLIST: <RUNNING | NOT RESPONDING | UNKNOWN>
        :param process_name: The name of the process to query [str]
        """
        filter_token = 'IMAGENAME eq {process_name}'.format(process_name=process_name)
        return Utils.get_process_status_tasklist(filter_token, process_name)

    @staticmethod
    def wait_for_disk_write(file_handler):
        """
        Wait for a file to finish the write.
        This is needed only when the data written to the file needs to be written in synchronous mode since by default
        the data are cashed by the python interpreter and the operating system
        :param file_handler: the file handler to wait for the writing
        """
        file_handler.flush()
        os.fsync(file_handler.fileno())

    @staticmethod
    def get_unique_elements_from_sequence(sequence):
        """Get unique elements from a sequence.
        :param sequence: Python sequence"""
        seen = set()
        return [x for x in sequence if not (x in seen or seen.add(x))]

    @staticmethod
    def get_shared_location():
        """
        Returns: Path to the public repository easily accessed by FPT, Roznov and other sites. Builds are stored in this
        location.
        """
        if PLATFORM == 'Windows':
            return SharedDriveMountingUtils.SHARED_DRIVE_SHORT_PATH
        elif PLATFORM == 'Linux':
            return SharedDriveMountingUtils.LINUX_MOUNT_PATH
        else:
            raise Exception("{platform} OS not yet supported.".format(platform=PLATFORM))

    @staticmethod
    def get_shared_resources_location(mapped_drive=False):
        """
        Returns: Path to the shared resources(artifacts, tools, kits, etc) for the automation framework
        :param mapped_drive: The location is determined relative to a mapped network drive
        """
        if PLATFORM == 'Windows':
            if mapped_drive:
                # Check if the shared drive is mounted or not. If not => mount it.
                SharedDriveMountingUtils().check_and_mount_shared_drive(
                    drive_path=SharedDriveMountingUtils.DRIVE_PATH,
                    shared_drive_path=SharedDriveMountingUtils.PROCESSOR_EXPERT_AUTO_MOUNT_PATH
                )
                return r'Z:\\'
            else:
                return SharedDriveMountingUtils.PROCESSOR_EXPERT_AUTO_MOUNT_PATH
        elif PLATFORM == 'Linux':
            return SharedDriveMountingUtils.LINUX_MOUNT_PATH
        else:
            raise Exception('{0} OS not yet supported'.format(PLATFORM))

    @staticmethod
    def get_debug_location():
        """
        Function has been declared here for future use in statistics.
        Returns: Path to the debug directory which stores logs from all build plans.
        """
        return os.path.join(Utils.get_shared_resources_location(), 'Builds', 'Debug')

    @staticmethod
    def get_instance_from_name(name, *args):
        """
        Creates an instance of a class based on its name. The name is expected to be given as module.class
        If called with args, will pass them to the function constructor, for non-static classes
        :param name: Class name in the form of module.class
        :return: An instance of the class
        """
        # Class name is expected to be in the form of a.b.c.class_name, where a.b.c is the module name
        if '.' not in name:
            return None

        module_name = importlib.import_module('.'.join(name.split('.')[:-1]))
        class_name = name.split('.')[-1]
        cls = getattr(module_name, class_name)
        return cls(*args)

    @staticmethod
    def get_files(root, extension_filter=None, pattern_in_files=None, depth=None, verbose_enabled=False,
                  flags=0):
        """
        Recursively seek all files with a specific extension [optional] under a root location
        :param root: The root where to start seeking the files from
        :param extension_filter: Extensions to seek for [None by default, means seek all files]
        :param pattern_in_files: Regular expression to be matched by file names [optional]
        :param depth: Maximum level of recursion, i.e depth=1 means only the given folder without subfolders
        :param verbose_enabled: Enable verbose mode
        :param flags: Default is 0, which means None. The following options are available:
                        2 = re.I = re.INGORECASE = sre_compile.SRE_FLAG_IGNORECASE # ignore case
                        4 = re.L = re.LOCALE = sre_compile.SRE_FLAG_LOCALE # assume current 8-bit locale
                        8 = re.M = re.MULTILINE = sre_compile.SRE_FLAG_MULTILINE # make anchors look for newline
                        16 = re.S = re.DOTALL = sre_compile.SRE_FLAG_DOTALL # make dot match newline
                        32 = re.U = re.UNICODE = sre_compile.SRE_FLAG_UNICODE # assume unicode locale
                        64 = re.X = re.VERBOSE = sre_compile.SRE_FLAG_VERBOSE # ignore whitespace and comments

                        In order to use more than one flag, they must be piped together. Example: flags = re.I | re.L
        :return: The list of files [empty list of root does not point to a directory]
        """
        if verbose_enabled:
            print(root)

        leaves = []
        if not os.path.isdir(root) or not os.path.exists(root):
            if verbose_enabled:
                print("Could not find the specified folder!")

            return leaves

        root = root.rstrip(os.sep)
        dir_cnt = root.count(os.sep)

        for dir_path, dirs, files in os.walk(root):
            if depth and dir_path.count(os.sep) == (dir_cnt + depth):
                break

            for file_name in files:
                file_path = os.path.join(dir_path, file_name)
                extension = os.path.splitext(file_path)[1]
                if verbose_enabled:
                    print("filename = " + file_name + " file_path = " + file_path + " extension = " + extension)

                if extension_filter is None or extension in extension_filter:
                    if not pattern_in_files:
                        leaves.append(file_path)
                    elif re.search(pattern_in_files, file_name, flags):
                        leaves.append(file_path)

        return leaves

    @staticmethod
    def get_file_extension(file_):
        """
        Returns the extension of a file
        :param file_: File to calculate extension for
        :return: the file extension with the . prefix. For example for the file test.txt the return is .txt
        In case the file does not exist an exception is raised
        """
        if not os.path.isfile(file_):
            raise Exception("{0} does not denote a file".format(file_))

        return os.path.splitext(file_)[1]

    @staticmethod
    def get_folders(root, match_patterns=None, depth=None, verbose_enabled=False):
        """
        Recursively seek all folders whose names match a given a list of folders [only names not full paths]
        under a root location
        :param root: The root where to start seeking the folders
        :param match_patterns:
        A _list_ of patterns the folder names have match [i.e. the folder name must include the pattern]
        If None, all folders under the root path will be returned
        :param depth: Maximum level of recursion, i.e depth=1 means only the given folder without subfolders
        TODO: add regex match
        :param verbose_enabled: Enable verbose mode
        :return: The list of folders in absolute path format. [empty list of root does not point to a directory]
        """
        if verbose_enabled:
            print(root)

        folders = list()
        if not os.path.isdir(root) or not os.path.exists(root):
            if verbose_enabled:
                print("Could not find the specified folder!")

            return folders

        root = root.rstrip(os.sep)
        dir_cnt = root.count(os.sep)

        for dir_path, dirs, files in os.walk(root):
            if depth and dir_path.count(os.sep) == (dir_cnt + depth):
                break

            for dir_name in dirs:
                if match_patterns is None:
                    folders.append(os.path.join(dir_path, dir_name))
                else:
                    for pattern in match_patterns:
                        if pattern in dir_name:
                            folders.append(os.path.join(dir_path, dir_name))

        return folders

    @staticmethod
    def delete_folders(root, match_patterns=None, verbose_enabled=False):
        """
        Deletes all folders whose names match a given a list of folders [only names not full paths]
        under a root location
        :param root: The root where to start seeking the folders
        :param match_patterns:
        A list of patterns the folder names have match [i.e. the folder name must include the pattern]
        If None, all folders under the root path will be returned
        TODO: add regex match
        :param verbose_enabled: Enable verbose mode
        """

        dirs = Utils.get_folders(root, match_patterns=match_patterns, verbose_enabled=verbose_enabled)
        for d in dirs:
            if os.path.exists(d):
                Utils.remove_path(d)

    @staticmethod
    def make_dirs(path, force_clean=True):
        """
        Creates a leaf directory and all intermediate ones only if the path does not exist.
        If the force_clean value is True and the path exists the content will be removed.
        :param path: The path to the directory that have to be created
        :param force_clean: True/False
        """
        if os.path.exists(path):
            if force_clean:
                Utils.delete_dir_content(path)
        else:
            os.makedirs(path)

    @staticmethod
    def merge_files_content(paths, path_to_merged_content, extension_filter=None, verbose_enabled=False):
        """
        Merge the content of files having a certain extension into a single file
        :param paths: the list of files or/and folders from which will extract the files to be merged
        :param extension_filter: extension to seek for
        :param path_to_merged_content: the path to the file were the merge result can be found
        :param verbose_enabled: enable verbose mode
        :return: True if successfully merged file contents
        """
        files = []
        for path in paths:
            if not os.path.exists(path):
                if verbose_enabled:
                    print('Unable to merge files; input list contains invalid path {0}!'.format(path))

                return False

            if os.path.isdir(path):
                if isinstance(extension_filter, str):
                    files.extend(Utils.get_files(path, extension_filter=(extension_filter, )))
                elif isinstance(extension_filter, list):
                    files.extend(Utils.get_files(path, extension_filter=tuple(extension_filter)))
            else:
                if extension_filter is not None and extension_filter != os.path.splitext(path)[1].lower():
                    continue
                files.append(path)

        if not files:
            print 'No files with extensions {0} to be merged in paths {1}'.format(
                ','.join(map(str, extension_filter)),
                ','.join(map(str, paths)))

            return True  # nothing to merge

        with open(path_to_merged_content, 'w') as result:
            for file_ in files:
                with open(file_, 'r') as f:
                    result.write(f.read())
                result.write(os.linesep)
                if verbose_enabled:
                    print 'Merged content of {0} to {1}'.format(file_, path_to_merged_content)

            # Wait for the data to be written to disc
            Utils.wait_for_disk_write(result)

        return True

    @staticmethod
    def filter_files(root, extension_filters, verbose_enabled=False):
        """
        Remove unnecessary data; keep only files with extension in <extensionFilters>
        :param root: starting folder
        :param extension_filters: list of files that must be kept
        :param verbose_enabled: enable verbose mode
        """
        if not os.path.isdir(root) or not os.path.exists(root):
            if verbose_enabled:
                print "Could not find the specified folder!"
            return

        if verbose_enabled:
            print "\nFilter content:"
        for dirpath, dirs, files in os.walk(root):
            for filename in files:
                fname = os.path.join(dirpath, filename)
                extension = os.path.splitext(fname)[1]
                if extension not in extension_filters:
                    os.remove(fname)
                    if verbose_enabled:
                        print "Removed file " + fname
        for dirpath, dirs, files in os.walk(root):
            for dir_ in dirs:
                directory = os.path.join(dirpath, dir_)
                if not os.listdir(directory):
                    os.rmdir(directory)
                    if verbose_enabled:
                        print "Removed folder " + directory
            if not os.listdir(dirpath):
                os.rmdir(dirpath)
                if verbose_enabled:
                    print "Removed folder " + dirpath
        if verbose_enabled:
            print "\n"
        return

    @staticmethod
    def append_to_archive(archive, files, compress_level=None):
        """
        Adds to an archive a list of files with folder structure preservation
        :param archive: The archive name
        :param files: The files to append
        :param compress_level: Compression level (optional)
        """
        os.chdir(os.path.dirname(archive))
        level = '' if compress_level is None else '-mx{0}'.format(compress_level)
        command = '7z a -r -tzip {1} {0}'.format(archive, level)
        for f in files:
            command = '{0} {1}'.format(command, f)

        Utils.run_subprocess(command, print_stdout=False)

    @staticmethod
    def unpack(archive, destination=None, mode='7zip', include_filters=tuple(), exclude_filters=tuple()):
        """
        Unpacks an archive preserving full directory structure in a given location.
        If destination is missing the archive will be unpack in its parent directory
        :param archive: The full path of the archive to be unpacked
        :param destination: Location where to unpack the archive
        :param mode: Mode to identify tool used for unpacking (7zip, zipfile)
        :param include_filters: List of file matching patterns used for unpacking only specific
        files or directories. The list of patterns should follow the specific syntax used by
        the unpacking tool. While '7zip' and 'unzip' tools use a glob-style syntax, the
        patterns used for the 'zipfile' tool should follow the regex syntax.
        :param exclude_filters: List of patterns to exclude specific files from unpacking.
        """
        dst_path = destination or os.path.dirname(archive)
        if PLATFORM == "Windows":
            quote = '"'
        elif PLATFORM == "Linux":
            quote = "'"
        else:
            quote = ""

        if mode == '7zip':
            unpack_cmd = '7z x -aoa -y "{0}"'.format(archive)
            unpack_cmd += ''.join(' {quote}-ir!{flt}{quote}'.format(quote=quote, flt=flt) for flt in include_filters)
            unpack_cmd += ''.join(' {quote}-xr!{flt}{quote}'.format(quote=quote, flt=flt) for flt in exclude_filters)

            Utils.run_subprocess(unpack_cmd, print_stdout=False, cwd=dst_path)
        elif mode == 'zipfile':
            zf = zipfile.ZipFile(archive)

            members = zf.namelist()

            if include_filters:
                members = filter(lambda x: any([bool(re.match(r, x)) for r in include_filters]), members)
            if exclude_filters:
                members = filter(lambda x: all([not bool(re.match(r, x)) for r in exclude_filters]), members)

            zf.extractall(path=dst_path, members=members)
        elif mode == 'unzip':
            unpack_cmd = 'unzip -o {0} -d {1}'.format(archive, dst_path)
            unpack_cmd += ''.join(" '{0}'".format(filter_) for filter_ in include_filters)
            if exclude_filters:
                unpack_cmd += ' -x'
            unpack_cmd += ''.join(" '{0}'".format(filter_) for filter_ in exclude_filters)

            Utils.run_subprocess(unpack_cmd, print_stdout=False)
        else:
            raise Exception('Specified mode: {} for unpacking is not recognized'.format(mode))

    @staticmethod
    def pack(content, archive, compress_level=None, mode='7zip', exclude_list=tuple(), remove_git_skeleton=True):
        """Packs a content into an archive

        :param content: A list of paths to be included into the archive
        :param archive: The full path of the archive to be created
        :param compress_level: Compression level (optional)
        :param mode: Mode to identify tool used for packing (7zip, zipfile)
        :param exclude_list: List of directories to exclude from packing (tuple)
        :param remove_git_skeleton: Flag which indicates whether the git skeleton should be removed
        """

        print("Packing mode selected: '{}'".format(mode))

        if not content:
            print("Nothing to be archived!")
            return

        if not isinstance(content, list):
            raise Exception('Invalid argument for routine {0}. '
                            'A list was expected for the first argument, instead got {1}'.
                            format(inspect.currentframe().f_code.co_name, type(content)))

        # delete the archive if it already exists
        if os.path.isfile(archive):
            os.remove(archive)

        # Define errors dict. Used for printing in case of errors
        errors_dict = dict()

        if mode == '7zip':
            exclude_cmd = ""
            if exclude_list:
                exclude_cmd += " ".join(["-x!{0}".format(exclusion) for exclusion in exclude_list])

            level = '' if compress_level is None else '-mx{0}'.format(compress_level)

            pack_cmd = (
                "7z a -tzip {level} -xr!.git {archive_name} {content} {exclusions}" if remove_git_skeleton else
                "7z a -tzip {level} {archive_name} {content} {exclusions}"
            )

            Utils.run_subprocess(pack_cmd.format(
                level=level,
                archive_name=archive,
                content=content[0],
                exclusions=exclude_cmd
            ), print_stdout=False)

            for item in content[1:]:
                Utils.append_to_archive(archive, item)

        elif mode == 'zipfile':
            content[0] = (
                os.getcwd() if "." == content[0]
                else Utils.normalize_path_name(path_name=content[0], verbose_enable=False)
            )

            print(
                "Content to upload into ZIP file '{archive}':{line_sep}{content}".format(
                    archive=archive, line_sep=os.linesep, content=content)
            )

            zf = zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED)

            print("Dirs to exclude from ZIP file '{archive}': {line_sep}{exclude_list}".format(
                archive=archive, line_sep=os.linesep, exclude_list=exclude_list))

            for root, sub_dirs, files in os.walk(content[0]):
                for item in sorted(sub_dirs) + files:
                    path = os.path.join(root, item)

                    # Skip newly create archive file from being added to the ZIP file
                    if os.path.basename(archive) in path:
                        continue

                    # Skip adding excluded dirs into ZIP file if correct pattern is found in file path
                    if any(dir_name and dir_name in path for dir_name in exclude_list):
                        continue

                    try:
                        zf.write(path, os.path.relpath(path, os.path.dirname(archive)))
                    except Exception as err:
                        errors_dict[path] = str(err)
            zf.close()

        elif mode == "zip":
            speed = "-{speed}".format(speed=compress_level) if compress_level else ""
            exclude_git_cmd = '-x ".git/*"' if remove_git_skeleton else ""

            exclude_list_cmd = ""
            if exclude_list:
                exclude_list_cmd = "-x {exclusions}".format(
                    exclusions=" ".join('"{0}"'.format(pattern) for pattern in exclude_list))

            exclude_cmd = " ".join((exclude_git_cmd, exclude_list_cmd))

            pack_cmd = 'zip -r {level} {archive} "{source}" {exclude}'.format(
                level=speed,
                archive=archive,
                source=content[0],
                exclude=exclude_cmd
            )

            Utils.run_subprocess(pack_cmd, print_stdout=False)

        else:
            raise Exception('Specified mode: {} for packing is not recognized'.format(mode))

        # Raise error if some files could not be zipped
        if errors_dict:
            raise ValueError(
                "Error when trying to pack files using mode '{mode}'!{line_sep}"
                "Please check errors dictionary:{line_sep}{err_dict}".
                format(mode=mode, line_sep=os.linesep, err_dict=dumps(errors_dict, indent=4))
            )

    @staticmethod
    def remove_from_archive(archive, content, mode="7zip"):
        """
        Removes a list of files/folders from an archive
        :param archive: Archive where to remove the content from
        :param content: Content [list of paths relative to the archive root] to be removed
        :param mode: Mode to identify tool used for packing (7zip, zip, zipfile). Default is 7zip.
        """
        if mode == "7zip":
            for item in content:
                Utils.run_subprocess('7z d {0} -r {1}'.format(archive, item), print_stdout=False)
        elif mode == "zip":
            delete_entries_cmd = "zip -d {archive} {items}".format(
                archive=archive,
                items=" ".join('"{0}/*"'.format(pattern) for pattern in content))

            Utils.run_subprocess(delete_entries_cmd, print_stdout=False, return_when_error=True)
        else:
            return

    @staticmethod
    def delete_dir_content(root, exclusions=None):
        # type: (str, tuple) -> None
        """
        Recursively deletes the contents of a directory, except the directory itself and a list of optional exceptions
        :param root: The directory whose content to delete [str]
        :param exclusions: A tuple of entries not to be deleted [tuple]
        """
        if exclusions is None:
            exclusions = tuple()

        for entry in os.listdir(root):
            path_to_delete = os.path.join(root, entry)

            if ((entry in exclusions) or (path_to_delete in exclusions)):
                continue

            if os.path.isfile(path_to_delete):
                os.remove(path_to_delete)
                continue

            match = False
            for exclusion in exclusions:
                if Utils.in_directory(exclusion, path_to_delete):
                    match = True
                    break

            shutil.rmtree(path_to_delete) if not match else Utils.delete_dir_content(path_to_delete, exclusions)

    @staticmethod
    def exclude_dirs(dirs, patterns):
        """
        Helper method used for removing unwanted dirs from os.walk loop.
        os.walk yields a 3-tuple of the form (dirpath, dirnames, filenames)
        :param dirs: dirnames
        :param patterns: list of patterns to exclude
        """

        dirs_index = 0
        while dirs_index < len(dirs):
            current_dir = dirs[dirs_index]
            for pattern in patterns:
                if fnmatch.fnmatch(current_dir, "*{0}*".format(pattern)):
                    dirs.remove(dirs[dirs_index])
                    dirs_index -= 1
                    break
            dirs_index += 1

    @staticmethod
    def onerror(func, path, exc_info):
        """Error handler for ``shutil.rmtree``.
        It attempts to add write permission to read only files and then retries.
        :param func: Self-explanatory
        :param path: Path
        :param exc_info: Required due to <shutil.rmtree> 'onerror' implementation
        """
        try:
            os.chmod(path, stat.S_IWUSR)
            func(path)
        except Exception as e:
            # Ignore errors encountered for .git hidden folder.
            if '.git' in path:
                return

            print('Got exception while removing path {0}. Exception: {1}'.format(path, repr(e)))

    @staticmethod
    def remove_path(path):
        """Wrapper function over shutil.rmtree() in order to fix Error 5 from Windows on file delete operation."""
        if not path:
            print('No path supplied!')
            return

        if not os.path.exists(path):
            print('Path {0} not found!'.format(path))
            return

        try:
            print('Attempt to remove path {0}'.format(path))
            if os.path.isdir(path):
                shutil.rmtree(path, onerror=Utils.onerror)
            else:
                os.remove(path)

            print('Removed specified path {0} with success!'.format(path))
        except OSError:
            print('Could not remove specified path {0}!'.format(path))

    @staticmethod
    def remove(file_):
        """
        Removes file/directory from a specified location using system calls, in order to avoid access errors.
        Args:
            file_: directory/file to be deleted
        """
        if PLATFORM == 'Windows':
            os.system('rm -r "{0}"'.format(file_))
        elif PLATFORM == 'Linux':
            os.system('rm -r "{0}"'.format(file_))
        else:
            raise Exception('Current operating system not supported: {0}'.format(PLATFORM))

    @staticmethod
    def rename_folder(folder_name_and_path, new_folder_name_and_path):
        """ Renames a folder
        :param folder_name_and_path: absolute folder path and name of folder to be renamed
        :param new_folder_name_and_path: absolute folder path and new name of folder
        """
        if os.path.exists(folder_name_and_path) and os.path.isdir(folder_name_and_path):
            os.rename(folder_name_and_path, new_folder_name_and_path)
        else:
            raise Exception('Folder path {0} does not exist!'.format(folder_name_and_path))

    @staticmethod
    def in_directory(child, directory):
        """
        Determines if a child path is included into a parent path. Child can denote a file or directory
        while parent can denote only a directory
        :param child: Child item, can be a file or directory
        :param directory: Parent directory
        :return: True, if child is contained in the directory or any of its subdirectories, False otherwise
        """

        # convert to absolute path
        child = os.path.realpath(child)
        directory = os.path.realpath(directory)

        # if an existing path is neither file or folder, most probably it's a folder with a OS-forbidden name
        # [e.g. starting with a . in Windows]
        is_dir = os.path.isdir(directory) or (not os.path.isfile(directory) and not os.path.isdir(directory))

        if not is_dir:
            raise Exception('Cannot determine if a file [{0}] path is included in another file [{1}] path. '
                            'The 2nd argument of "in_directory" must be a directory'.format(child, directory))

        # return true, if the common prefix of both is equal to directory
        # e.g. /a/b/c/d.rst and directory is /a/b, the common prefix is /a/b
        return os.path.commonprefix([child, directory]) == directory

    @staticmethod
    def get_env(key, default_value=None):
        """
        Gets the value of an environment variable
        :param key: Name of the environment variable
        :param default_value: The optional argument to specify the default value in case the environment variable
               is missing
        :return: The value of the environment variable or 'default_value' if the environment variable has not been
                 defined
        """
        return os.getenv(key, default_value)

    @staticmethod
    def set_env(key, value):
        """
        Sets and environment variable with a string formatted value
        :param key: Environment variable
        :param value: Value of environment variable
        """
        os.environ['{0}'.format(key)] = '{0}'.format(value)

    @staticmethod
    def merge_tree(src, dst, overwrite=True):
        """
        Merge [by copy] the content of `src` folder into `dst` folder.
        :param src: The folder whose content will be merged
        :param dst: The folder where to merge `src`
        :param overwrite: Overwrite files in `dst`
        """

        for root, dirs, files in os.walk(src):
            dst_dir = root.replace(src, dst, 1)
            if not os.path.exists(dst_dir):
                os.makedirs(dst_dir)
            for file_ in files:
                src_file = os.path.join(root, file_)
                dst_file = os.path.join(dst_dir, file_)

                if os.path.exists(dst_file):
                    if overwrite:
                        os.remove(dst_file)
                        shutil.copy(src_file, dst_dir)
                else:
                    shutil.copy(src_file, dst_dir)

    @staticmethod
    def replace_in_tree(root, seek_for, replace_with, excluded_dirs=None):
        """
        Traverses a root dir down to its full depth and replaces a token in files/dirs name and files content
        :param root: The root dir where to start the replacing
        :param seek_for: Token to seek in files/dirs name and files content
        :param replace_with: Token to replace with in files/dirs name and files content
        :param excluded_dirs: A list of dirs excluded from the replace operation. Their children are excluded too
        """
        if excluded_dirs is None:
            excluded_dirs = []

        print 'Replacing and/or renaming {0} with {1} in {2}{3}'.format(
            seek_for, replace_with, root, '' if not excluded_dirs else (', excluding: ' + str(excluded_dirs)))

        dirs_to_be_renamed = []
        files_to_be_renamed = []
        for (path, dirs, files) in os.walk(root):
            if seek_for in path:
                dirs_to_be_renamed.append(path)
            for file_ in files:
                file_path = os.path.join(path, file_)
                if seek_for in os.path.basename(file_path):
                    files_to_be_renamed.append(file_path)

                # check if file is part of an excluded directory
                match = False
                for e in excluded_dirs:
                    if Utils.in_directory(file_path, e):
                        match = True
                        break

                # do not replace in files which belong to excluded folders
                if not match and \
                        os.path.exists(file_path) and \
                        Utils.replace_tokens_in_text_file(file_path, [seek_for], [replace_with]):
                    print 'Replaced in {0}'.format(file_path)

        for file_path in files_to_be_renamed:
            # Rename only the file name leaving its parent tree unchanged, because the dirs will be modified afterwards
            rename_to = os.path.join(os.path.dirname(file_path),
                                     os.path.basename(file_path).replace(seek_for, replace_with))
            if os.path.exists(file_path):
                print 'Renaming {0} to {1}'.format(file_path, rename_to)
                os.rename(file_path, rename_to)

        for dir_ in dirs_to_be_renamed:
            rename_to = dir_.replace(seek_for, replace_with)
            if os.path.exists(dir_):
                print 'Renaming {0} to {1}'.format(dir_, rename_to)
                os.rename(dir_, rename_to)

    @staticmethod
    def replace_tokens_in_text_file(file_path, search_for, replace_with):
        """
        Replaces a list of tokens with another list of tokens in a text file
        :param file_path: Text file path
        :param search_for: List of tokens to search for [can be regexes]
        :param replace_with: List of tokens used for replacing
        :return: The list of tokens to be replaced has been found in the file
        """

        if not os.path.exists(file_path):
            raise Exception('{} does not denote a valid path'.format(file_path))

        if not os.path.isfile(file_path):
            raise Exception('{} does not denote a file'.format(file_path))

        if Utils.is_binary(file_path):
            return  # this is a binary file therefore no replacement will take place

        if not isinstance(search_for, list) or not isinstance(replace_with, list):
            raise Exception('Invalid arguments. Both should be of list type')

        if len(search_for) != len(replace_with):
            raise Exception('Both list arguments should have the same number of elements')

        found = False
        temp_file = file_path + datetime.now().strftime('%Y-%m-%d-%H-%M-%S-%f') + '.temp'

        if len(temp_file) >= Utils.get_max_path():
            temp_file = file_path + '.temp'

        with open(file_path, 'r') as input_file:
            with open(temp_file, 'w+') as dest:
                for line in input_file:
                    new_line = line
                    for s_token, r_token in zip(search_for, replace_with):
                        tmp_new_line = new_line
                        if s_token in line:
                            found = True
                            new_line = new_line.replace(s_token, r_token)
                            if new_line == tmp_new_line:
                                print(
                                    "error in function {function} for file {file_path}."
                                    " multiple token included in each other".format(
                                        function=inspect.currentframe().f_code.co_name,
                                        file_path=file_path
                                    )
                                )
                        elif re.search(s_token, line):  # check if regex has a match
                            try:
                                new_line = re.sub(s_token, r_token, new_line)
                            except:  # noqa: E722
                                print(
                                    "error in function {function} for file {file_path}."
                                    " re.sub({search_token}, {replace_token}, {new_line}) failed".format(
                                        function=inspect.currentframe().f_code.co_name,
                                        file_path=file_path,
                                        search_token=s_token,
                                        replace_token=r_token,
                                        new_line=new_line
                                    )
                                )
                                found = False
                            else:
                                found |= (r_token in new_line)  # replacements were performed
                            if not found:
                                new_line = tmp_new_line
                    dest.write(new_line)

        with open(temp_file, 'r') as input_file:
            with open(file_path, 'w+') as dest:
                for line in input_file:
                    dest.write(line)
                # wait for the write to finish
                Utils.wait_for_disk_write(dest)
        os.remove(temp_file)

        return found

    @staticmethod
    def wait_for_file_write_access(file_, timeout):
        """
        Wait for a file to have write access to.
        Exception is raised if write access cannot be permitted within a given timeout
        :param file_: the file to aceess
        :param timeout: the timeout [in seconds] to wait until write access is permitted
        """
        start_time = time()

        # wait for a timeout so that the file gets released, in case it's used by another process
        while True:
            elapsed = time() - start_time
            if elapsed > timeout:
                raise Exception('File {} is still in use by another process '
                                'after waiting {} seconds to be released'.format(file_, timeout))

            # noinspection PyBroadException
            try:
                with open(file_, 'a+'):
                    pass  # do nothing, the file is not used by any other process -> exit loop
                break
            except Exception:
                # let other threads to execute for a bit, then continue to wait until file is released or timeout passes
                print 'File {} seems locked by another process. Waiting {} seconds to be released'.\
                    format(file_, timeout - elapsed)
                sleep(0.1)

    @staticmethod
    def replace_placeholders(text, placeholders):
        """ Performs replacements of placeholders in given text if they exist.
        :param text: text where placeholders should be replaced
        :param placeholders: mapping between placeholder name and value
        """
        for placeholder, placeholder_value in placeholders.iteritems():
            text = text.replace(placeholder, placeholder_value)
        return text

    @staticmethod
    def _get_output(pipe, capture_list, ended_event, print_output):
        """
        Internal method (used from within a thread object) for capturing live output from a running subprocess
        :param pipe: output stream to read from
        :param capture_list: list where output lines are gathered
        :param ended_event: event to signal termination
        :param print_output: whether to print captured output on stdout as well
        """
        '''The loop is terminated by the empty string sentinel when stream EOF is reached'''
        for i in iter(pipe.readline, ''):
            capture_list.append(i.rstrip('\n'))
            if print_output:
                print i
        '''Stream has reached EOF, signal termination and return'''
        ended_event.set()

    @staticmethod
    def kill_process(process):
        """
        Forcibly terminate process
        :param process: a process instance created via subprocess.Popen
        """
        if process is not None:
            if PLATFORM == 'Windows':
                os.system('TASKKILL /F /PID {0} /T'.format(process.pid))
            else:
                process.kill()

    @staticmethod
    def kill_process_tree(proc, timeout=None):
        """Kill a process tree (including grandchildren)
        :param proc: subprocess.Popen or psutil.Process instance
        :param timeout: Expressed in seconds. Default is None.
        """
        parent_pid = proc.pid

        try:
            process = psutil.Process(parent_pid)
            children = process.children(recursive=True)
            proc.terminate()
            for child in children:
                child.terminate()

            _, alive = psutil.wait_procs(children.append(proc), timeout=timeout)
            for survivor in alive:
                Utils.kill_process(survivor)

        except psutil.NoSuchProcess:  # terminate orphan processes, if any
            for process in psutil.process_iter():
                if process.ppid() == parent_pid:
                    try:
                        process.terminate()
                        process.wait(timeout=timeout)
                    except psutil.TimeoutExpired:
                        Utils.kill_process(process)

    @staticmethod
    def run_subprocess(command, command_input=None, print_stdout=True, print_stderr=True,
                       env=None, cwd=None, kill_after_timeout=-1, shell=True, wait_for_process_end=True,
                       stdout_file=None, stderr_file=None, return_when_error=False, verbose=True):
        """
        Executes a command (process with arguments), captures and optionally prints stdout, stderr and returns code
        :param command: command to execute
        :param command_input: list of commands to be sent to process input stream
        :param print_stdout: display the content of stdout
        :param print_stderr: display the content of stderr
        :param env: environment to be passed to `subprocess.Popen` call
        :param cwd: the child's current directory to be passed to `subprocess.Popen` call
        :param kill_after_timeout: grace interval measured in seconds child processes are allowed to run until expired
        than child processes will be terminated forcibly. Default value -1 indicates will not be applied forcibly
        termination of child processes.
        :param shell: override the shell argument of the subprocess.Popen() function
        :param wait_for_process_end: wait for the process to finish before returning.
                                     In such case stderr and stdout returns will be None
        :param stdout_file: File where to write STDOUT content
        :param stderr_file: File where to write STDERR content
        :param return_when_error: Flag that indicates if sp, out, err will be returned in case of error
        :param verbose: Get verbose on messages printed on screen

        :return return code, stdout and stderr output
        Notes: stdout and stderr output is captured and returned regardless of the print_stdout/stderr arguments.
        If print_stdout/stderr is requested, the respective output is printed on the console. Output from stderr is
        printed separately from stdout output for clarity
        """

        if verbose:
            print('Executing command: {0}'.format(command))

        if command_input:
            if type(command_input) is list:
                commands = '\n'.join(c for c in command_input)
                print('Input of command = {0}'.format(commands))
                stdin = subprocess.PIPE
            else:
                raise Exception('Input for subprocess is not a list')
        else:
            commands = None
            stdin = None

        sp = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=stdin, bufsize=1,
                              shell=shell, env=env, cwd=cwd)

        if not wait_for_process_end:
            return sp, None, None

        kill_timer = None
        if kill_after_timeout != -1:
            kill_timer = threading.Timer(kill_after_timeout, SubprocessUtils.kill_subprocess, [sp])
            kill_timer.start()

        out, err = SubprocessUtils.manage_subprocess_streams(sp, command_input=commands, print_stdout=print_stdout)
        if kill_timer is not None:
            kill_timer.cancel()

        if err and print_stderr:
            print('###### Stderr ######')
            print(err)

        if verbose:
            print('Return code = {0}'.format(sp.returncode))

        if sp.returncode != 0:
            if stdout_file:
                print("STDOUT file: '{0}'".format(stdout_file))
                try:
                    with open(stdout_file, 'w') as fd_out:
                        fd_out.write(str(out))
                        Utils.wait_for_disk_write(fd_out)
                except Exception as error:
                    print("Error when trying to preserve STDOUT in file: '{0}'\n{1}".format(stdout_file, error))
            if stderr_file:
                print("STDERR file: '{0}'".format(stderr_file))
                try:
                    with open(stderr_file, 'w') as fd_out:
                        fd_out.write(str(err))
                        Utils.wait_for_disk_write(fd_out)
                except Exception as error:
                    print("Error when trying to preserve STDERR in file: '{0}'\n{1}".format(stderr_file, error))

            if return_when_error:
                return sp, out, err

            raise Exception('Execution of command {0} resulted in error'.format(command))

        return sp, out, err

    @staticmethod
    def run_subprocess_with_input(command, print_stdout=True, env=None, command_input=None):
        """
        Executes a command (process with arguments), prints stdout, stderr and return code
        :param command: command to execute
        :param print_stdout: display the content of stdout
        :param env: environment to be passed to `subprocess.Popen` call
        :param command_input: input for the command (The order of execution is "command; command_input")
        :return process instance, stdout and stderr value
        """
        print 'Executing command: {0}'.format(command)
        sp = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=1, shell=True, env=env,
                              stdin=subprocess.PIPE)

        # Capture output lists
        out, err = [], []
        out_ended, err_ended = threading.Event(), threading.Event()

        # Threads for monitoring outputs
        thread.start_new_thread(Utils._get_output, (sp.stdout, out, out_ended, print_stdout))
        thread.start_new_thread(Utils._get_output, (sp.stderr, err, err_ended, False))

        if command_input:
            if type(command_input) is list:
                print 'Input of command = {0}'.format('\n'.join(c for c in command_input))
                sp.stdin.write('\n'.join(c for c in command_input))
            else:
                raise Exception('Input for subprocess is not a list')

        sp.stdin.close()
        # wait for termination
        out_ended.wait()
        err_ended.wait()

        sp.wait()

        out = '\n'.join(out)
        err = '\n'.join(err)

        if err:
            print '###### Stderr ######'
            print err

        print 'Return code = {0}'.format(sp.returncode)

        if sp.returncode != 0:
            raise Exception('Execution of command {0} resulted in error'.format(command))

        return sp, out, err

    @staticmethod
    def run_subprocess_powershell(command=None, env=None):
        """Executes a command (process with arguments), prints stdout, stderr and return code

        :param command: command to execute
        :param env: environment to be passed to `subprocess.Popen` call

        :return process instance, stdout and stderr value
        """

        if command:
            print('Executing command:'
                  '{linesep}{cmd}'.format(linesep=os.linesep, cmd=command))

            # Check if [command] is list
            # This is needed if someone wants to run Powershell scripts with script param (NOT POWERSHELL PARAM)
            if type(command) is list:
                sp = subprocess.Popen(command,
                                      stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE,
                                      bufsize=1,
                                      shell=True,
                                      env=env
                                      )

                (out, err) = sp.communicate()

                if err:
                    raise Exception('Error: ' + str(err))

                return out

        return None

    @staticmethod
    def get_filtered_dir_content(path, regex):
        """
        Returns a list of files in a folder filtered by a regex
        :param path: folder path
        :param regex: regex to filter with
        :return: list of files [including]
        """
        return [f for f in os.listdir(path) if re.match(regex, f)]

    @staticmethod
    def change_eol_in_file(path, eol_search_for, eol_replace_with):
        """
        Change the line ending of a file
        :param path: path to file
        :param eol_search_for: actual line ending of the file
        :param eol_replace_with: future line ending of the file
        """
        with open(path, 'rb') as f:
            content = f.read()
            content = content.replace(eol_search_for, eol_replace_with)

        with open(path, 'wb') as f:
            f.write(content)
            Utils.wait_for_disk_write(f)

    @staticmethod
    def is_binary(file_path):
        """
        Heuristically determines if a file is binary
        :param file_path: File to be analyzed
        :return: The file is binary
        """
        # most binary files contain a \0 marker
        with open(file_path, 'rb') as f:
            for block in f:
                if '\0' in block:
                    return True

        # some binary files do not contain the \0 marker so we need a more in-depth analysis
        # this is a memory consuming operation as the whole file content is analyzed
        with open(file_path) as f:
            s = f.read()
            return not Utils.is_text(s)

    @staticmethod
    def is_text(s, text_characters="".join(map(chr, range(32, 127))) + "\n\r\t\b", threshold=0.30):
        """
        Determines heuristically if a string represents a text or not
        :param s: string to be analyzed
        :param text_characters:the text definition [set of characters] against which to compare the string
        :param threshold: accepted percent of text characters vs non-text ones
        :return: The given string is represents a text
        """
        _null_trans = string.maketrans("", "")

        # if s contains any null, it's not text:
        if "\0" in s:
            return False
        # an "empty" string is "text" (arbitrary but reasonable choice):
        if not s:
            return True
        # Get the substring of s made up of non-text characters
        t = s.translate(_null_trans, text_characters)
        # s is 'text' if less than 30% of its characters are non-text ones:
        return float(len(t)) / float(len(s)) <= threshold

    @staticmethod
    def is_unicode(s):
        """
        Determines if a string contains unicode characters
        :param s: string to be analyzed
        :return: `True` is the given string contains unicode characters, `False` otherwise
        """

    @staticmethod
    def is_numeric(s):
        """
        Determines if a string contains numeric characters only
        :param s: string to be analyzed
        :return: `True` is the given string contains numeric characters, `False` otherwise
        """
        try:
            float(s)
            return True
        except (ValueError, TypeError):
            return False

    @staticmethod
    def update_path_in_path_env_variable(path_to_be_replaced, new_path, add_new_path=False):
        """
        Replace a single path in PATH environment variable.
        This script doesn't replace sub-paths.
        :param path_to_be_replaced: The path to be replaced.
        :param new_path: The replacement path.
        :param add_new_path: True if we want to add the path to PATH environment variable. This means that there is
        no path to update. (path_to_be_replaced is not in the PATH environment variable)

        Example of usage
        update_path_in_path_env_variable('C:\\COSMIC\\bin', 'C:\\COSMIC_4_3_9\\bin')
        """
        # TODO throw exception if PATH is bigger then 1024
        path = Utils.get_env('PATH')

        if path is None and add_new_path is False:
            raise Exception('PATH environment variable doesn\'t exist')
        elif path is None and add_new_path is True and os.name == 'posix':
            with open("/etc/environment", "a") as f:
                f.write('PATH=\"' + new_path + "\"")
                Utils.wait_for_disk_write(f)
            Utils.run_subprocess('source /etc/environment')
            # no need to treat else case for Windows, setx creates new PATH environment variable.

        if new_path == "":
            raise Exception('No replacement string has been specified.')
        elif path_to_be_replaced == "":
            raise Exception('No string to replace has been specified.')

        if path.count(path_to_be_replaced) > 1:
            raise Exception('Several paths named {0} have been found. Please add ";" '
                            'to the end of the path or be more specific.'.format(path_to_be_replaced))

        if not os.path.isabs(path_to_be_replaced):  # check if this denotes one path and the path is valid
            raise Exception('{0} does not denote a path'.format(path_to_be_replaced))
        elif not os.path.isabs(new_path):
            raise Exception('{0} does not denote a path'.format(new_path))

        # TODO this case seems to not exist. Could treat case if variable has spaces.
        if path == "" and add_new_path is False:
            raise Exception('PATH environment variable is empty. Nothing to replace')
        elif path == "" and add_new_path is True:
            if os.name == 'nt':
                Utils.run_subprocess('setx /M PATH "{0}"'.format(new_path))
            elif os.name == 'posix':
                Utils.replace_tokens_in_text_file('/etc/environment', ['PATH='], ['PATH=\"' + new_path + "\""])
                Utils.run_subprocess('source /etc/environment')
            else:
                raise Exception("Unsupported OS {0}".format(os.name))

        # After all conditions are met path is replaced. This is the usual case
        if os.name == 'nt':
            updated_path = string.replace(path, path_to_be_replaced, new_path)
            Utils.run_subprocess('setx /M PATH "{0}"'.format(updated_path))
        elif os.name == 'posix':
            Utils.replace_tokens_in_text_file('/etc/environment', [path_to_be_replaced], [new_path])
            Utils.run_subprocess('source /etc/environment')
        else:
            raise Exception("Unsupported OS {0}".format(os.name))

        return

    @staticmethod
    def get_subdirs(dir_):
        """
        Determines all the subdirectories of a given dir, recursively
        :param dir_: The dir whose subdirectories to determine
        :return: The list of child subdirectories
        """
        result = []
        for root, dirs, _ in os.walk(dir_):
            [result.append(os.path.join(root, d)) for d in dirs]

        return result

    @staticmethod
    def get_info_from_csv_file(input_files):
        """
        Reads a CSV file and returns all its entries (rows) in it into a list of dictionaries e.g.:
        Given C1...Cn columns, from which M of them are filled with values Cm1...Cmn we return M dictionaries as
        follows:Dx["C1"]=Cx1,Dx["C2"]=Cx2 Dx[Cn]=Cxn. All the dictionaries will be appended in a list: L=[D1,D2...Dn]
        and the list is returned
        Args:
            input_files: Input CSV file(s)
        Returns: all the info contained in the CSV file
        """
        info = []
        input_files = [input_files] if isinstance(input_files, str) else input_files
        for input_file in input_files:
            with open(input_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    row_dict = dict()
                    for key, value in row.items():
                        '''Remove empty entries'''
                        if value:
                            r'''
                            Decode the string in order to get rid of special characters resulted from csv.DictReader(f)
                            e.g.:'\ xef \ xed\ xec Req ID' is transformed into u'Req ID'
                            '''
                            row_dict[key.decode('utf-8-sig')] = value
                    if row_dict:
                        info.append(row_dict)
        return info

    @staticmethod
    def filter_dataset(dataset, values_filter=None, keys_filter=None):
        """
        Args:
            dataset: list of dictionaries with all the information read from requirements file
            values_filter: dictionary containing all the conditions a resource must meet. eg.:
                    filter_['Traceability'] = 'Traceable'
                    filter_['Fulfilled'] = 'EAR'
            keys_filter: list of requested keys from the data set, e.g: ['Req ID'] returns
            {'Req ID':[list of all the entries.]}
        Returns:
            A dictionary containing the keys_filter parameters as keys and the matching resources
            as values in a list.
        """

        if values_filter is None or type(values_filter) is not dict:
            values_filter = dict()

        if keys_filter is None or type(keys_filter) is not list:
            keys_filter = []

        matching_data = dict.fromkeys(keys_filter, [])
        for entry in dataset:
            if all(i in entry.keys() for i in values_filter.keys()):
                if all(i in entry.values() for i in values_filter.values()):
                    for k, v in entry.iteritems():
                        if not keys_filter or k in keys_filter:
                            matching_data[k].append(entry[k])

        return matching_data

    @staticmethod
    def read_design_id_info_in_file(file_):
        """
        Finds all the design ids in a xmi file based on a standard pattern, returning them to the user as a list.
        Args:
            file_: Input file. Needs to be XMI, otherwise, an exception will be raised. This is generated automatically
            by the Enterprise Architect tool.
        Returns:
            design_ids: list in which will be appended all design ids present in the eap project.
        """

        if not file_.endswith('.xmi'):
            raise Exception('Wrong input file, expected XMI file type for parsing, received {0}'.format(file_))

        design_info = []
        line_number = -1
        try:
            with open(file_, 'r') as f:
                for line_number, line in enumerate(f, 0):
                    match = re.search('<UML:Diagram name="(.+?)"', line.decode("utf-8-sig", "strict").strip())
                    match_criteria = re.search('diagramType="ActivityDiagram"',
                                               line.decode("utf-8-sig", "strict").strip())
                    if match and match_criteria and match.group(1) not in design_info:
                        design_info.append(match.group(1))
        except UnicodeDecodeError, e:
            raise Exception("UTF-8 decoding error {0} in file {1} at line {2}".format(e, file_, line_number))
        except IOError, e:
            message = "I/O error {0} in file {1}".format(e, file_)
            if line_number != -1:
                message += " at line {0}".format(line_number)
            raise Exception(message)
        return design_info

    @staticmethod
    def read_design_id_info(files_):
        """
        Read design_id from multiple design files
        Args:
            files_: Input file or file list.
        Returns:
            design_infos: list in which will be appended all design ids present in eap project(s).
        """

        design_infos = []
        file_list = files_ if isinstance(files_, list) else [files_]
        for file_ in file_list:
            design_infos.extend(Utils.read_design_id_info_in_file(file_))

        return design_infos

    @staticmethod
    def get_design_to_code_map(directory, design_ids, extensions='.c'):
        """
        Finds in a directory the design ids which should be written in the source code using a certain pattern.
        Parses all the files having the  .c extension and returns the location of the finding, and the line in a tuple.
        Eg: pattern is: ' Implements (.+?)_Activity', and we are looking for 'enetif_low_level_output' in 'ports'
        directory. Return value will be {'enetif_low_level_output': ('ports\\netif\\enetif\\enetif.c', 'line: 87')}
        Args:
            directory: Directory in which the design id needs to be put
            design_ids: list of all the design ids which need to be found
            extensions: tuple containing all the extensions in which the pattern('Implements (.+?)_Activity')
                        can be found. EG: extensions = ('.c','.h')
        Returns: A dictionary, having the design ids given as a list as keys and the file and line as value:
        d[design_id] = (sourcefile.c, line line_num)
        If design_id is not found, value will be None.
        """
        d = dict.fromkeys(design_ids, None)
        os.chdir(directory)
        for root, dirs, files in os.walk('.'):
            for name in files:
                name = os.path.realpath(os.path.join(root, name))
                if name.endswith(extensions):
                    line_num = 0
                    with open(name, 'r') as f:
                        for line in f:
                            line_num += 1
                            match = re.search('Implements (.+?)_Activity', line)
                            if match and match.group(1) in design_ids:
                                if d[(match.group(1))] is None:
                                    '''Create first entry in dictionary'''
                                    d[(match.group(1))] = \
                                        list((os.path.relpath(name, directory), 'line: ' + str(line_num)))
                                else:
                                    '''Append to list if multiple entries exist'''
                                    d[(match.group(1))].append(
                                        (os.path.relpath(name, directory), 'line: ' + str(line_num)))
        return d

    @staticmethod
    def get_requirement_to_design_mapping(file_):
        """
        Parses an eap file exported in XMI format
        Args:
            file_: xmi input file
        Returns: dictionary containing requirements to design_ids mapping:
            e.g: {req1: [did_1], req2: [did1,did2]}
        """
        if not file_.endswith('xmi'):
            raise Exception('Please check input, need an .xmi file, received: {0}'.format(file_))

        dict_ = dict()
        root = ET.parse(file_)
        for element in root.findall('.//elements/element'):
            for requirement in element.findall('requirements/requirement'):
                try:
                    if not requirement.attrib['name'].rstrip() in dict_.keys():
                        '''Create empty list for newly found element'''
                        dict_[requirement.attrib['name'].rstrip()] = []
                    dict_[requirement.attrib['name'].rstrip()].append(element.attrib['name'])

                except KeyError:
                    '''If key error has occurred, we have found elements in the .xmi files who do not have
                    'name' argument in their attributes, element is invalid and must not be taken into consideration'''
                    pass

        return dict_

    @staticmethod
    def cross_p_join(*args, **kwargs):
        """Cross platform join:
        Overwrites the os.join function to use '/' separator, instead of default os.sep
        This works for cross OS code, web, ftp.
        """

        return os.path.join(*args, **kwargs).replace(os.sep, '/')

    @staticmethod
    def clean_directory_customized(path, patterns_to_search):
        # type: (str, tuple) -> None
        """Delete sub-dirs with a specific pattern contained
        :param path: full path to dir [str]
        :param patterns_to_search: tuple of strings to search in dir (tuple)
        :return None
        """
        for dir_path, dir_names, file_names in os.walk(path):
            for dir_name in dir_names:
                if any([pattern_to_search in dir_name for pattern_to_search in patterns_to_search]):
                    dir_to_remove = os.path.join(path, dir_name)
                    Utils.remove_path(dir_to_remove)

    @staticmethod
    def force_clean(force_clean, dir_to_empty, dirs_to_skip=()):
        """ Method to delete sub-directories from a base directory

        :param force_clean: True/False
        :param dir_to_empty: Base directory to empty
        :param dirs_to_skip: List of directories to skip (sub directories of base dir)

        :return: True, on success
                 False, on fail
        """

        if not force_clean:
            return False

        if not dir_to_empty:
            return False

        print("Directory to empty: \n\t[{dir}]".format(dir=dir_to_empty))

        if not os.path.isdir(dir_to_empty):
            print("\n\tDirectory does not exist!")
            return False

        print("\n\tDirectory exists!")
        # Get only first level content for base directory
        list_of_sub_dirs = None
        iterations = 0
        for directory, sub_dirs, files in os.walk(dir_to_empty):
            if iterations == 1:
                break

            list_of_sub_dirs = sub_dirs
            iterations += 1

        if not list_of_sub_dirs:
            print("Could not find any sub-directories into: [{dir}]\n".format(dir=dir_to_empty))
            return False

        for sub_dir in list_of_sub_dirs:
            # If there is no directory to skip when cleaning just skip
            if dirs_to_skip and sub_dir in dirs_to_skip:
                continue

            path_to_sub_dir = os.path.join(dir_to_empty, sub_dir)
            print("\n\tSub-dir to delete: [{sub_dir_path}]\n".format(sub_dir_path=path_to_sub_dir))
            try:
                shutil.rmtree(path_to_sub_dir)
            except Exception as err:
                print("\n\tError when trying to remove directory: [{dir}]\n\t\t{err}".
                      format(dir=path_to_sub_dir, err=err))

        return True

    @staticmethod
    def copy_customized(source, destination, ext, destination_cleanup=False, verbose=False):
        """
        Copies files with a certain extension from source to destination
        :param source: source folder
        :param destination: destination folder
        :param ext: file extension to search for
        :param destination_cleanup: cleanup destination before copy
        :param verbose: true or false
        """

        # Checks if source folder is empty and stops process
        try:
            if os.path.isdir(source):
                length = len(os.listdir(source))
                if length < 1:
                    raise Exception('Source folder {0} is empty!'.format(source))
            else:
                raise Exception('Source folder {0} does not exist or is not a directory!'.format(source))
        except Exception as e:
            print('Path error: %s' % e)

        try:
            # Cleanup destination folder before copying
            if destination_cleanup is True:
                if os.path.exists(destination):
                    Utils.remove_path(destination)

            files = glob.iglob(os.path.join(source, ext))
            for file_ in files:
                if os.path.isfile(file_):
                    if verbose:
                        print("INFO: Copying {0} into {1}".format(file_, destination))
                    shutil.copy2(file_, destination)
        # Directories are the same
        except shutil.Error as e:
            print('Directory not copied. shutil error: %s' % e)
        # Any error saying that the directory doesn't exist
        except OSError as e:
            print('Directory not copied. OSError: %s' % e)

    @staticmethod
    def copy_directory(source, destination, ignore_patterns=None, destination_cleanup=False):
        """Copies directory from source to destination.
        :param source: source folder
        :param destination: destination folder
        :param ignore_patterns: a tuple for of copytree()'s function ignore argument, ignoring files and
        directories that match one of the glob-style patterns provided
        :param destination_cleanup: cleanup `destination` before copy
        """

        # Checks if source dir exists
        if not os.path.isdir(source):
            raise Exception('Source folder {0} does not exist or is not a directory!'.format(source))

        # Check if source dir is empty
        if not [entry for entry in os.listdir(source) if not entry.startswith('.')]:
            raise Exception('Source folder {0} is empty!'.format(source))

        try:
            # Cleanup destination folder before copying
            if destination_cleanup:
                if os.path.exists(destination):
                    Utils.remove_path(destination)

            if ignore_patterns:
                ignore_ = shutil.ignore_patterns(*ignore_patterns)
            else:
                ignore_ = None

            shutil.copytree(source, destination, symlinks=True, ignore=ignore_)

        # Directories are the same
        except shutil.Error as e:
            print('Directory not copied. shutil error: %s' % e)
            return False

        # Any error saying that the directory doesn't exist
        except OSError as e:
            print('Directory not copied. OSError: %s' % e)
            return False

        return True

    @staticmethod
    def create_section_from_message(text,
                                    header_line='**************************************************',
                                    line_beautification=True,
                                    word_beautification=True):
        """
        Prints a message enclosed by two header lines, optionally using line and word beautification style
        :param text: text to be printed
        :param header_line: header line used to encapsulate the text
        :param line_beautification: split the message into multiple lines, if needed
        :param word_beautification: print each word on the same line
        """

        if len(header_line) == 0:
            raise Exception('Header line must not be empty')

        # calculate an adaptive line length
        max_line_length = len(header_line) - (2 if len(header_line) > 2 else 0) \
            if line_beautification \
            else len(text)

        # in case word beautification is not possible, don't apply it
        if word_beautification and any(len(word) >= max_line_length for word in text.split(' ')):
            word_beautification = False

        final_text = header_line

        if line_beautification:
            printed = 0
            while printed < len(text):
                line_length = 0
                for word in text[printed:].split(' ') if word_beautification else text[printed:]:
                    if (line_length + len(word) + 1) <= max_line_length + 1:
                        line_length += len(word) + 1
                    else:
                        break

                line = text[printed:printed + line_length]
                final_text += '{0}{1}'.format(os.linesep, line)
                printed += len(line)
        else:
            final_text += '{0}{1}'.format(os.linesep, text)

        final_text += '{0}{1}'.format(os.linesep, header_line)
        return final_text

    @staticmethod
    def print_with_header(text,
                          header_line='**************************************************',
                          line_beautification=True,
                          word_beautification=True):
        """
        Prints a message enclosed by two header lines, optionally using line and word beautification style
        :param text: text to be printed
        :param header_line: header line used to encapsulate the text
        :param line_beautification: split the message into multiple lines, if needed
        :param word_beautification: print each word on the same line
        """

        print Utils.create_section_from_message(text,
                                                header_line=header_line,
                                                line_beautification=line_beautification,
                                                word_beautification=word_beautification)

    @staticmethod
    def padding(nr_of_padding, char=" "):
        """
        Pads with a certain character for a number of padding positions
        :param nr_of_padding - the number of padding positions
        :param char - the padded character, default is space/empty string
        :return the padded string object
        """
        return char * nr_of_padding

    @staticmethod
    def get_known_scripting_file_extensions():
        """
        Returns a list with the most common scripting file extensions
        """
        return ['xml', 'py', 'pl', 'bat', 'sh', 'php', 'vbs', 'js']

    @staticmethod
    def get_known_compilable_code_file_extensions():
        """
        Returns a list with the most common compilable code file extensions
        """
        return ['c', 'cpp', 'h', 'hpp', 'java', 'cs']

    @staticmethod
    def get_known_source_code_file_extensions():
        """
        Returns a list with the most common compilable code file extensions
        """
        return Utils.get_known_compilable_code_file_extensions() + Utils.get_known_scripting_file_extensions()

    @staticmethod
    def copy(source, destination):
        """
        Copy files from source to destination using system calls, in order to avoid Error 2/22 raised by shutil library,
        when copying from one drive to another
        Args:
            source: source directory/file
            destination: destination directory/file
        """
        if PLATFORM == 'Windows':
            os.system(r'COPY "{0}" "{1}"'.format(source, destination))
        elif PLATFORM == 'Linux':
            os.system(r'cp "{0}" "{1}"'.format(source, destination))
        else:
            raise Exception('Current operating system not supported: {0}'.format(PLATFORM))

    @staticmethod
    def xcopy(source, destination):
        """
        Copy files from source to destination using system calls, in order to avoid  OSError: [Error 183]
        Cannot create a file when that file already exists ---> destination path
        raised by shutil library,
        when copying from one drive to another and destination already exists
        Merge equivalent from source to destination
        Args:
            source: source directory/file
            destination: destination directory/file
            /s /e Use this option to copy directories, subdirectories, and the files contained within them,
             in addition to the files in the root of source. Empty folders will also be recreated.
            /y Use this option to stop the xcopy command from prompting you about overwriting files from source
            that already exist in destination.
            /i Use the /i option to force xcopy to assume that destination is a directory.
            /f Display the full path and file name of both the source and destination files being copied
        """
        if PLATFORM == 'Windows':
            os.system('XCOPY "{0}" "{1}" /s /e /y /i /f'.format(source, destination))
        elif PLATFORM == 'Linux':
            os.system('cp "{0}" "{1}"'.format(source, destination))
        else:
            raise Exception('Current operating system not supported: {0}'.format(PLATFORM))

    @staticmethod
    def move(source, destination):
        """
        Copy and delete files from source to destination using system calls, in order to avoid Error 2/22 raised by
        shutil library when copying from one drive to another
        Args:
            source: source directory/file
            destination: destination directory/file
        """
        if PLATFORM == 'Windows':
            os.system('MOVE {0} {1}'.format(source, destination))
        elif PLATFORM == 'Linux':
            os.system('mv {0} {1}'.format(source, destination))
        else:
            raise Exception('Current operating system not supported: {0}'.format(PLATFORM))

    @staticmethod
    def post_release_operations(branch, release_tags,
                                repo_tag_mappings, repo_project_mappings, cwd):
        """Update and tag a desired branch after a release by performing the following operations:
            - merge driver code from version found in tag defined in manifest file
            - push changes into desired branch
            - apply release tag on the desired branch
        :param branch: Name of the branch where repos will be merged
        :param release_tags: Name of the release tags
                             (E.g: drivers: BLN_SMCAL_4.3_S32G2XX_EAR_0.4.2,
                                   tests: BLN_TEST_SMCAL_4.3_S32G2XX_EAR_0.4.2)
        :param repo_tag_mappings: Pairs repo, tag (E.g 'Can': 'BLN_CAN_001')
        :param repo_project_mappings: Pairs repo, project (E.g 'Can': 'MCAL')
        :param cwd: Current working directory
        """

        failed_drivers_or_tests = []
        for repo, tag in repo_tag_mappings.items():
            try:
                project = repo_project_mappings[repo]

                release_tag = release_tags['drivers']
                if repo.startswith('test'):
                    release_tag = release_tags['tests']

                if repo == 'vnv_config':
                    release_tag = release_tags['tests']

                Utils.run_subprocess(
                    'git clone ssh://git@bitbucket.sw.nxp.com/{project}/{repo}.git -b '
                    '{branch} {repo}'.format(project=project,
                                             repo=repo,
                                             branch=branch)
                )

                commands = [
                    'git rm -r *',
                    'git commit -m "Delete all items"',
                    'git archive -o {tag}.zip {tag}'.format(tag=tag),
                    'unzip -o {tag}.zip'.format(tag=tag),
                    'rm {tag}.zip'.format(tag=tag),
                    'git add -A',
                    'git commit -m "Merged tag {tag}"'.format(tag=tag),
                    'git push origin {branch}'.format(branch=branch),
                    'git tag {release_tag}'.format(release_tag=release_tag),
                    'git push origin {release_tag}'.format(release_tag=release_tag),
                ]

                Utils.run_subprocess(' && '.join(commands), cwd=os.path.join(cwd, repo))
            except:  # noqa: E722
                failed_drivers_or_tests.append(repo)
                continue

        if failed_drivers_or_tests:
            raise Exception('The following drivers/tests failed to update:\n{0}\n'
                            'Please check log for details'.format('\n'.join(failed_drivers_or_tests)))

    @staticmethod
    def get_exec_extension():
        """
        Returns the platform-specific executable extension
        :return: extension for executables
        """
        return '.exe' if PLATFORM == 'Windows' else ''

    @staticmethod
    def convert_xlsx_to_csv(xlsx_file_path):
        """
        Convert an xlsx file to csv format
        :param xlsx_file_path - path where xlsx file is located
        """

        try:
            workbook = xlrd.open_workbook(xlsx_file_path)
        except xlrd.XLRDError:
            raise Exception('Could not open .xlsx file: {0}'.format(xlsx_file_path))

        worksheet = workbook.sheet_by_index(0)
        with open(os.path.splitext(xlsx_file_path)[0] + ".csv", 'wb') as csv_file:
            writer_csv = unicodecsv.writer(csv_file, encoding='utf-8')
            for row_num in xrange(worksheet.nrows):
                writer_csv.writerow(worksheet.row_values(row_num))

    @staticmethod
    def get_max_path():
        """
        :return: Maximum path length allowed by the OS
        """
        if os.name == 'nt':
            import ctypes.wintypes
            return ctypes.wintypes.MAX_PATH

        if os.name == 'posix':
            return 4096

        raise Exception('Unsupported OS {}'.format(os.name))

    @staticmethod
    def wait(condition, timeout, blocking=False):
        """
        Waits as long as a condition is met or a timeout elapses.
        :param condition: wait condition [i.e. the wait happens as long as the condition is `True`]
        :param timeout: timeout [in seconds] to wait. when timeout elapses, exit from wait
        :param blocking: locks the execution to current thread
        :return: the actual amount of time [in seconds] spend in wait loop
        """
        start = datetime.now()
        while condition and (datetime.now() - start).seconds < timeout:
            if blocking:
                pass
            else:
                sleep(0.1)  # give other threads the chance to execute

        return (datetime.now() - start).seconds

    @staticmethod
    def resolve_host_ip(hostname, retries=1, return_when_error=False):
        """
        :param hostname: alias of the test machine in the dns server
        :return: local ip address of the host
        """
        while retries:
            out = Utils.run_subprocess(('ping {0}' if PLATFORM == 'Windows' else 'ping {0} -c 4')
                                       .format(hostname), return_when_error=return_when_error)[1]
            host_ip = None
            for line in out.splitlines():
                if PLATFORM == 'Windows':
                    match = re.match('Reply from (.+?): bytes', line)
                elif PLATFORM == 'Linux':
                    match = re.match('64 bytes from (.+?): icmp_seq', line)
                else:
                    raise Exception('Current OS not yet supported {0}'.format(PLATFORM))
                if match:
                    host_ip = match.group(1)
                    break

            retries -= 1
            if host_ip is not None:
                break

        if not host_ip:
            raise Exception("Cannot find ip address of the machine for {0} dns name.".format(hostname))
        return host_ip

    @staticmethod
    def create_file_from_content(file_, content, overwrite=False):
        """
        Create a new/override existing file with a given content
        :param file_: file to be created
        :param content: content to be put into the file
        :param overwrite: remove file in case it exists
        :return:
        """
        if os.path.exists(file_) and not overwrite:
            raise Exception('File {} already exists'.format(file_))

        with open(file_, 'w+' if overwrite else 'w') as f:
            f.write(content)
            Utils.wait_for_disk_write(f)

    @staticmethod
    def get_boolean_value(string_value, default_value=False):
        """
        Gets the boolean value of a string
        :param string_value: the string to be converted
        :param default_value: the default value function returns if string_value is None
        """
        return util.strtobool(string_value) if string_value is not None else default_value

    @staticmethod
    def fill_test_info(std_err, traceability_info_file, configuration):
        """
        Parses the output from functional testing and converts it to a list
        :param std_err: standard output from the functional testing
        :param traceability_info_file: file containing test cases and their details
        :param configuration: string to describe the product calling this method
        :return: test_info: a list of tests and their results in human readable format
        """
        test_info = []
        test_names_and_descriptions = {}

        with open(traceability_info_file, 'r') as f:
            for line in f:
                dict_ = literal_eval(line)
                test_names_and_descriptions[dict_['test_case']] = dict_['details']

        for line in std_err.splitlines():
            if 'test_' in line:
                if line.endswith('... ok'):
                    result = 'PASSED'
                elif '... skipped' in line:
                    result = 'SKIPPED'
                else:
                    result = 'FAILED'
                line = line.partition(' ')[0]
                test_info.append({'Test ID': line.partition(' ')[0], 'result': result, 'Configuration': configuration,
                                  'Test Description': test_names_and_descriptions[line]})

        return test_info

    @staticmethod
    def get_most_recent_build(dir_path):
        """
        Get the name of the most recent build/modification done in dir_path.

        Example:
        If we create 190620 dir and after that 180620, the algorithm will return most recent modification:
        180620
        :param dir_path: directory which holds the build
        :return: name of the directory which represents most recent build/change
        """
        # bd = build dir
        dirs = [bd for bd in os.listdir(dir_path) if os.path.isdir(os.path.join(dir_path, bd)) and bd.isdigit()]

        max_dirs_window = min(len(dirs), 5)
        i = 0
        most_recent_time = 0
        most_recent_build = 0
        while i < max_dirs_window:
            candidate_build = dirs[-1 - i]
            dir_time = os.path.getctime(os.path.join(dir_path, candidate_build))
            if most_recent_time < dir_time:
                most_recent_time = dir_time
                most_recent_build = candidate_build
            i += 1

        return most_recent_build

    @staticmethod
    def normalize_path_name(path_name=None, verbose_enable=True):
        """Normalize a pathname by collapsing redundant separators and up-level references so that A//B, A/B/, A/./B and
        A/foo/../B all become A/B.
        On Windows, it converts forward slashes to backward slashes. To normalize case, use normcase().

        :param path_name: Path to apply os.path.normpath() on it [string | list]
        :param verbose_enable: Get verbose about method actions (boolean)
        :raise ValueError, no path supplied
                           path is not string type
        :return Normalized path (+ join elements if path_name is list)
        """

        if not path_name:
            raise ValueError('No path supplied to apply "normpath"')

        if isinstance(path_name, list):
            return os.path.normpath(os.path.join(*path_name))

        if verbose_enable:
            print("Supplied path is not list but: '{0}'".format(type(path_name)))

        # Check Python version
        py3_check = sys.version_info[0] == 3
        if py3_check:
            string_type = str,
        else:
            string_type = basestring, str, unicode

        if isinstance(path_name, string_type):
            return os.path.normpath(path_name)

        default_string_to_return = "<COULD_NOT_PRINT_STRING_AS_METHOD_INPUT_ARG_IS_NOT_[STRING-TYPE]>"
        with Utils().TrialContextManager():
            default_string_to_return = str(path_name)

        raise ValueError(
            'Supplied path "{0}" is not string but "{1}"'.format(default_string_to_return, type(path_name))
        )

    @staticmethod
    def check_and_mount_shared_drive(
            drive_path, shared_drive_path=None, force_unmap=False, use_shell_cmds=False, verbose=False
    ):
        """Checks and mounts the network shared storage under Windows.
        This method is a wrapper over <SharedDriveMountingUtils.check_and_mount_shared_drive> and its used to expose it
        to the world.
        :param drive_path: Drive path where to mount network shared drive [str]
        :param shared_drive_path: Full path to the shared drive to mount [str]
        :param force_unmap: Force the drive to unmap [bool]
        :param use_shell_cmds: Execute (un)mount operations by using SHELL cmds [bool]
        :param verbose: Get verbose about the output [bool]
        """
        shared_drive_mount_utils = SharedDriveMountingUtils(
            drive_path=drive_path,
            shared_drive_path=shared_drive_path
        )

        shared_drive_mount_utils.check_and_mount_shared_drive(
            use_shell_cmds=use_shell_cmds,
            force_unmap=force_unmap,
            verbose=verbose
        )

    @staticmethod
    def get_file_name(file_path, with_extension=False):
        """"
        Returns the file name (w/o its extension) from its full path
        :param file_path: The file full path
        :param with_extension: If `True`, the file extension is returned along with its name.
        """
        if not os.path.isfile(file_path):
            raise Exception("{0} does not denotes a valid file".format(file_path))

        full_file_name = os.path.basename(file_path)

        if with_extension:
            return full_file_name

        return os.path.splitext(full_file_name)[0]

    @staticmethod
    def retry(method, *args, **kwargs):
        """Wrapper to retry on any exception."""

        retries = kwargs.pop("retry_times", 20)

        try:
            retries = int(retries)
            if retries < 1:
                raise Exception("Could not cast to integer.")
        except:  # noqa: E722
            raise Exception("Number of retries {0} must be a positive integer".format(str(retries)))

        msg = None
        while retries:
            try:
                method(*args, **kwargs)
            except Exception as exception:
                print("[{0}] {1}, retries left:{2}".format(method.__name__, exception, retries))
                retries -= 1

                sleep(5)
            else:
                print("[{0}] OK".format(method.__name__))
                break
        else:
            raise Exception("[retry][{0}] FAILED : {1}".format(method.__name__, msg))

    @staticmethod
    def parse_xml_file(xml_file):
        """Parse an xml file and return the dom object.
        :param xml_file: The xml file
        :return: The xml dom object
        """

        try:
            parsed_xml = minidom.parse(xml_file)
        except ExpatError:
            exception_type, exception_value, _ = sys.exc_info()
            raise Exception('Failed to parse {0}, error encountered is: {1}'.format(
                xml_file, format_exception_only(exception_type, exception_value)[0].strip()
            ))
        except Exception:
            exception_type, exception_value, _ = sys.exc_info()
            raise Exception('An unexpected error occurred while trying to parse {0}: {1}'.format(
                xml_file, format_exception_only(exception_type, exception_value)[0].strip()
            ))

        return parsed_xml

    @staticmethod
    def file_is_locked(file_path):
        """
        Check if a file has a lock on it.
        :param file_path: path to the target file.
        """
        if os.path.exists(file_path) and os.path.isfile(file_path):
            try:
                with open(file_path, 'ab', 16):
                    return False
            except IOError:
                return True
        else:
            warnings.warn("Provided path doesn't exist or is not a file: {0}".format(file_path), stacklevel=2)
            return


class ConversionUtils(object):
    """
    Helper class for conversion between different document types
    """
    def __init__(self):
        pass

    @staticmethod
    def word2pdf(doc, pdf='', override=True, remove_source=False):
        """
        Converts a Microsoft Word (.doc or .docx formats) file to PDF
        :param doc the Word file name
        :param pdf The PDF file name.
        If empty string, the PDF will be created in the same location as the `doc` and have the same name
        :param override overrides if PDF already exists
        :param remove_source Remove the original doc after conversion
        """

        if PLATFORM != 'Windows':
            raise Exception('Word to PDF conversion is available only on Windows operating systems.')

        if not os.path.isfile(doc):
            raise Exception('Document to be converted ({0}) either does not exist or is not a file'.format(doc))

        if not pdf:
            pdf = os.path.splitext(doc)[0] + '.pdf'

        from win32com import client
        import pywintypes
        com_class = "Word.Application"

        try:
            com_instance = client.DispatchEx(com_class)
        except Exception as err:
            raise Exception("Invalid office installation on current build machine: {0}".format(err))

        if override and os.path.exists(pdf):
            os.remove(pdf)

        word = None
        try:
            word = com_instance.Documents.Open(doc, ReadOnly=1)
            word.SaveAs(pdf, FileFormat=17)
        except pywintypes.com_error:
            # in case of non existing COM class, refurbish a bit the exception message, then pass it to the caller
            raise Exception('COM class {0} does not exist'.format(com_class))
        finally:
            if word:
                word.Close()
            com_instance.Quit()

        # an extra check of the exported PDF existence
        if not os.path.isfile(pdf):
            raise Exception(
                '{0} does not exists. Check whether the {1} COM server is functional'.format(pdf, com_class))

        if remove_source:
            Utils.remove(doc)


class Resource(object):
    """Wrapper over resource, used to provide common access methods to resource's attributes/values"""

    # Key that should be present in a resource
    MANDATORY_KEY = 'type'

    def __init__(self, attributes):
        if not all(
                [(isinstance(attributes, dict), Resource.MANDATORY_KEY in [key.lower() for key in
                                                                           attributes.keys()])]
        ):
            raise Exception(
                'The object retrieved is not a valid resource (i.e. is not a dictionary or does not contain a '
                '{0!r}} key'.format(Resource.MANDATORY_KEY)
            )

        self.__attributes = attributes

    def __contains__(self, key):
        return key in self.__attributes

    def __getitem__(self, key):
        return self.__attributes[key]

    def __repr__(self):
        return repr(self.__attributes)

    def __iter__(self):
        return iter(self.__attributes.keys())

    def stringify(self):
        """Stringify a resource (as key1=value1, key2=value2 string)"""

        return ', '.join(
            ['{0!r}={1!r}'.format(key, value) for key, value in self.__attributes.items()]
        )


class RegexUtils(object):
    """
    Helper class targeted for regex operations
    """

    def __init__(self):
        pass

    @staticmethod
    def get_dont_match_pattern(*patterns):
        """
        :param patterns: pattern(s) NOT to be matched
        :return: the regex to be used for NOT matching a set of patterns
        """
        regex = r"^(?!.*\b("

        for p in patterns:
            regex += p + '|'

        regex = regex[:-1]  # remove last | character
        regex += r")\b)"

        return regex


class ComponentDictionary(object):
    """
    Helper class used to retrieve component info; it's a dictionary of tuples <component_id, 'Component' instance>
    """

    class Component(object):
        """
        Helper class - used to store data specific to a certain component.
        We'll store component data in a dictionary like
        {type1:[file_path1, file_path2, ...], type2:[file_path3, ...]}
        """

        def __init__(self):
            """Component name"""
            self.__name = None

            """Component specific configuration files"""
            self.__configuration_files = set()

            """The associated sources of this component stored as {source_type:<list_of_sources>}
            which will be considered for any analysis"""
            self.__analysis_set = dict()

            """Analysis that produces reports needs to be executed. By default, analysis is executed"""
            self.__analysis_executed = True

            """Any report ran over this component will be checked for metrics violations
            By default, all reports are checked"""
            self.__reports_are_checked = True

        def set_name(self, name_):
            """
            Set the component name
            :param name_: component name
            """
            self.__name = name_

        def get_name(self):
            """
            :return: Get component name
            """
            return self.__name

        def set_configuration_files(self, config_list_):
            """
            Set the configuration files
            :param config_list_: list of configuration files
            """
            self.__configuration_files = config_list_

        def get_configuration_files(self):
            """
            :return: Get configuration files
            """
            return self.__configuration_files

        def set_analysis_set(self, type_, source_list_):
            """
            Set the analysis set for a specific type
            :param type_: analysis type (e.g. files with *.c extension)
            :param source_list_: The source list of the given type_
            """
            self.__analysis_set[type_] = source_list_

        def get_analysis_set(self, type_):
            """
            :param type_: type set (e.g. files with *.c extension)
            :return: Get the source list to be analyzed for a given type_
            """
            if self.is_type_analyzed(type_):
                return self.__analysis_set[type_]
            return set()

        def get_analysis_types(self):
            """
            :return: List of types which will be analyzed for this component
            """
            return self.__analysis_set.keys()

        def is_type_analyzed(self, type_):
            """
            Check if a specific analysis type [e.g. a specific file extension] is to be analyzed
            :param type_: type to be analyzed(e.g. *.c files)
            :return: `True` if the set will be analyzed
            """
            return type_ in self.__analysis_set.keys()

        def set_analysis_is_executed(self, value):
            """
            Set whether to execute or not to execute the analysis of this component
            :param value: `True` if analysis should be executed, `False` otherwise
            """
            self.__analysis_executed = value

        def get_analysis_is_executed(self):
            """
            :return: True` if analysis should be executed
            """
            return self.__analysis_executed

        def set_reports_are_checked(self, value):
            """
            Set whether to check or not the reports obtained after analyzing the analysis set of this component
            :param value: `True` if reports are to be checked, `False` otherwise
            """
            self.__reports_are_checked = value

        def get_reports_are_checked(self):
            """
            :return: True` if reports are to be checked
            """
            return self.__reports_are_checked

    def __init__(self):
        """Known components will be stored in a dictionary
        {component_ID1:Component(), component_ID2:Component()}"""
        self.__components_dictionary = dict()

    def add_component(self, component_id, data):
        """
        Add a component to the dictionary
        :param component_id: unique component ID
        :param data: the corresponding Component object
        """
        if not isinstance(data, ComponentDictionary.Component):
            raise Exception('Invalid argument received for component ID {0}! It should be a '
                            'Component object.'.format(component_id))

        self.__components_dictionary[component_id] = data

    def get_component(self, component_id):
        """
        Get the component corresponding to the given component_id
        :param component_id the unique component ID [e.g. for SDK the name is built using name,
        type and variant name(if applicable)]
        :return: the Component object or raises KeyError if the component ID is unknown
        """
        return self.__components_dictionary[component_id]

    def has_component(self, component_id):
        """
        :param component_id: the component ID to test
        :return: True if the component was added to the dictionary
        """
        return component_id in self.__components_dictionary

    def remove_component(self, component_id):
        """
        Remove the component from the dictionary
        :param component_id: the ID of the component that must be removed from the dictionary
        """
        if self.has_component(component_id):
            del self.__components_dictionary[component_id]

    def get_components_ids(self):
        """
        :return: Get the ID list of known components
        """
        return self.__components_dictionary.keys()

    def get_analyzed_types(self, component_id):
        """
        Get the known file types for a certain component
        :param component_id: ID of the component
        :return: the list of known file types for the given component
        """
        return self.get_component(component_id).get_analysis_types()

    def get_analysis_set(self, components_ids=None, requested_types=None, verbose_enabled=True):
        """
        Get the lists of files and folders for the specified components
        :param components_ids: the list of components IDs that have to be inspected
        :param requested_types: the list of file types that must be returned
        :param verbose_enabled: enable verbose mode
        :return: a dictionary containing the file sets for the requested elements
        (e.g. for SDK {'C_SOURCE_TYPE':['f1.c', 'f2.c'], 'H_SOURCE_TYPE':['f3.h']})
        """
        if not any(self.__components_dictionary):
            raise Exception('The components dictionary is empty!')

        ''' check if the requested components names are valid '''
        for component_id in components_ids:
            if component_id not in self.__components_dictionary.keys():
                raise Exception('Invalid component ID {0} received as input!'.format(component_id))

            ''' check if the requested elements are known '''
            for type_ in requested_types:
                if type_ not in self.get_analyzed_types(component_id):
                    raise Exception('{0} file type not supported for {1}!'.format(type_, component_id))

            if verbose_enabled:
                print 'Component {0} will be analyzed.'.format(component_id)

        '''get the component files'''
        result = dict()
        for component_id in components_ids:
            component_data = self.__components_dictionary[component_id]
            for type_ in requested_types:
                values = set()
                if type_ in result.keys():
                    values = result[type_]
                values.update(component_data.get_analysis_set(type_))
                result[type_] = values
        return result

    def get_file_set(self, component_id):
        """
        Get the component file set
        :param component_id: component ID
        :return: all component files
        """
        component = self.get_component(component_id)
        file_set = set()
        for file_type in component.get_analysis_types():
            for file_ in component.get_analysis_set(file_type):
                file_set.add(file_)
        return file_set


class LayoutUtils(object):
    """
    Helper class used to extract the folders containing the data (list of files)
    for the components supported on the specified device
    """
    ''' LAYOUT path relative to the workingDir; here we'll move all build useful files'''
    LAYOUT_RELATIVE_PATH = 'layout'

    ''' TEMPORARY LAYOUT path relative to the workingDir; we use this dir for transfer between directories'''
    LAYOUT_TEMP_PATH = 'layout_temp'

    def __init__(self, device, working_dir, component_dictionary, verbose_mode):
        """Device name for which the layout is built."""
        self.__device = device

        """Working directory"""
        self.__working_dir = working_dir

        """Component dictionary"""
        self.__component_dictionary = component_dictionary

        """Print advanced debug messages"""
        self.__verbose_mode = verbose_mode

    def build_layout(self, layout_dir, empty_layout_folder=True):
        """
        Move the component files
        :param layout_dir: location where the build files will be moved to prepare the installer package
        :param empty_layout_folder: make sure that the new layout is built in an empty folder
        :return: path to the built layout
        """
        ''' create layout folder '''
        if os.path.exists(layout_dir) and empty_layout_folder:
            shutil.rmtree(layout_dir)

        if not os.path.exists(layout_dir):
            os.mkdir(layout_dir)

        '''length of working dir path including path separator'''
        wd_path_len = len(self.__working_dir) + len(os.path.sep)

        for cmp_id in self.__component_dictionary.get_components_ids():
            for file_ in self.__component_dictionary.get_file_set(cmp_id):
                file_path = os.path.dirname(file_)
                file_name = os.path.basename(file_)

                if self.__verbose_mode:
                    print 'Processing component {0}, file {1} from {2}'.format(cmp_id, file_name, file_path)

                '''get the path relative to the working dir'''
                wd_rel_file_path = file_path[wd_path_len:]

                '''build the path relative to the layout that must be built'''
                ld_rel_file_path = os.path.join(os.path.sep, layout_dir, wd_rel_file_path)

                '''it's possible that other component already created the folder'''
                if ld_rel_file_path and not os.path.exists(ld_rel_file_path):
                    os.makedirs(ld_rel_file_path)

                '''it's possible that other component already moved the file'''
                new_file = os.path.join(os.linesep, ld_rel_file_path, file_name)
                if not os.path.exists(new_file):
                    shutil.copy(file_, new_file)
                    if self.__verbose_mode:
                        print '\tCopied {0} to {1}'.format(file_, new_file)


class ResourceManager(object):
    """
    Class for managing a pool of shared resources
    Resources are described in /helper/resources.xml
    Exclusivity is implemented by the ResourceFileLock class
    Clients request exclusive access to a resource by calling get_resource method. The function blocks until
    it can get exclusive access to the requested resource (type) and returns a context manager Reservation that
    can be used in a 'with' statement, thus the reservation is automatically released once it gets out of scope
    Example:
    with ResourceManager().get_resource(resource-filter [where resource-filter is a dictionary]) as resource:
        do_something_with(resource)
    """

    class ResourceFileLock(FileLock):
        """
        Helper class implementing a simple file-based locking mechanism on a shared location
        The lock is not re-entrant
        """

        """Path to file based resources locks"""
        LOCK_PATH = os.path.join(Utils.get_shared_resources_location(), 'Builds', 'locks')

        """Suffix for lock files"""
        LOCK_SUFFIX = 'lock_'

        """A resource key which specifies the period after the lock file is removed when acquiring fails"""
        LOCK_LIFETIME_MARKER = 'lifetime'

        @staticmethod
        def _get_lock_path(key):
            # Sort the attributes by length in order to have relevant info first
            attrs = ['{0}_{1}'.format(*x) for x in key.items()]
            attrs.sort(lambda x_, y: cmp(len(x_), len(y)))
            lock_name = '_'.join(attrs)
            # Make sure the name has only valid characters
            lock_name = ''.join(
                c if c in '-_.()%s%s' % (string.ascii_letters, string.digits) else '_' for c in lock_name
            )
            # Limit to a reasonable size [i.e. max path limit as per OS constraints]
            path_prefix = os.path.join(ResourceManager.ResourceFileLock.LOCK_PATH,
                                       ResourceManager.ResourceFileLock.LOCK_SUFFIX)
            return path_prefix + lock_name

        def __init__(self, key):
            self.key = key
            # If the resource has lifetime defined in resources.xml than the lock will be kept a maximum of time
            # equal to lifetime.
            # time_of_existence(s) <= lifetime(s)
            self.lifetime = (
                self.key[ResourceManager.ResourceFileLock.LOCK_LIFETIME_MARKER] if
                ResourceManager.ResourceFileLock.LOCK_LIFETIME_MARKER in self.key else None
            )
            super(ResourceManager.ResourceFileLock, self).__init__(self._get_lock_path(self.key))

        def get_key(self):
            return self.key

    class Reservation(object):
        """
        Simple reservation system based on file locks
        Context-manager type of class; clients use it in 'with' constructs, resource is released automatically
        """

        def __init__(self, lock):
            if not isinstance(lock, ResourceManager.ResourceFileLock):
                raise Exception('Invalid lock type {0} passed to the Reservation constructor. '
                                'Expected: ResourceManager.ResourceFileLock'.format(type(lock)))

            if not lock.is_acquired():
                raise Exception('Illegal usage: argument lock {0} should already be acquired before its use'
                                .format(lock.get_key()))

            self.lock = lock

        def __enter__(self):
            return self.lock.get_key()

        def __exit__(self, type_, value, tb):
            """Release the exclusive lock """
            self.lock.release()

    def __init__(self):
        """
        Reads the configuration file
        """
        root = Utils.parse_xml_file(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'resources.xml'))
        self.resources = []
        for element in root.getElementsByTagName('resource'):
            resource = dict(element.attributes.items())
            self.resources.append(resource)

    def filter_resources(self, filter_):
        """

        Args:
            filter_: dictionary containing all the conditions a resource must meet. eg.:
                filter_['type'] = 'tcpipstack_functional_tests'
                filter_['key'] = self.settings.agent_id
        Returns: the resources from the XML file which match the criteria in filter_

        """
        matching_resources = []
        for r in self.resources:
            for key, value in filter_.iteritems():
                if key not in r:
                    break

                if value not in r.get(key).split(','):
                    break

            else:
                matching_resources.append(r)

        return matching_resources

    @staticmethod
    def get_free_resource_without_locking(resources):
        """
        check if the resource is currently used without locking it
        :param resources: list with the different resources to check
        :return free resources found or None if no free resource found
        """

        free_resources = []
        for r in resources:
            lock_path = ResourceManager.ResourceFileLock._get_lock_path(r)
            if not os.path.isfile(lock_path):
                free_resources.append(r)

        return free_resources if free_resources else None

    def get_resource(self, filter_, timeout=None):
        """
        Find a resource based on filtering criteria and reserve it
        If multiple resources match the criteria the first found will be reserved
        :param filter_: Filtering criteria dictionary
        :param timeout: An optional timeout parameter that allow the caller to impose a defined period for waiting a
        successful resource acquire
        """
        print('Requesting resource matching the following criteria: {0}'.format(filter_))

        requested_resources = self.filter_resources(filter_)
        # check if there are any such resources
        if not requested_resources:
            raise Exception('Unknown or unavailable resource requested matching filter: {0}'.format(filter_))

        # cycle through matching resources until we find a free one
        while True:
            if timeout:
                requested_resources_with_timeout = (
                    [resource for resource in requested_resources if not resource.get('lifetime')]
                )
                requested_resources_with_timeout.extend(
                    [resource for resource in requested_resources if all(
                        (resource.get('lifetime'), timeout < int(resource.get('lifetime')))
                    )]
                )

                for resource in requested_resources_with_timeout:
                    lock = ResourceManager.ResourceFileLock(resource)
                    if lock.acquire(timeout=timeout):
                        print('Acquired a free resource matching filter: {0}'.format(filter_))
                        return ResourceManager.Reservation(lock)
                raise AcquireResourceTimeoutError(timeout, requested_resources_with_timeout)
            else:
                for resource in requested_resources:
                    lock = ResourceManager.ResourceFileLock(resource)
                    if lock.lifetime:
                        # This case stops for the lock file hanging if the build has stopped before the lock
                        # has been released.
                        if lock.acquire(int(lock.lifetime)):
                            print('Acquired a free resource matching filter: {0}'.format(filter_))
                            return ResourceManager.Reservation(lock)
                        else:
                            # File descriptor does not exist. It was opened on another machine and left hanging there.
                            # Just removing the actual lock file.
                            print(
                                'This resource has timeout set to {} seconds Timeout expired, deleting resource'.format(
                                    lock.lifetime
                                )
                            )
                            Utils.remove(lock.get_lock_path())
                    else:
                        # This case waits forever for the lock to be acquired because the call is made in a loop.
                        if lock.acquire():
                            print('Acquired a free resource matching filter: {0}'.format(filter_))
                            return ResourceManager.Reservation(lock)


class UnbufferedOutput(object):
    """
    Wrapper class that encompasses a stream object and ensures
    unbuffered operation by adding a flush after each write
    """

    def __init__(self, stream):
        self.stream = stream

    def write(self, data):
        """Flush after each write"""
        self.stream.write(data)
        self.stream.flush()

    def __getattr__(self, attr):
        return getattr(self.stream, attr)


class SubprocessUtils(object):
    """
    Utilities used in run_subprocess implementation
    """

    def __init__(self):
        pass

    @staticmethod
    def get_output(pipe, capture_list, ended_event, print_output, out_stream=sys.stdout):
        """
        Internal method (used from within a thread object) for capturing live output from a running subprocess
        :param pipe: output stream to read from
        :param capture_list: list where output lines are gathered
        :param ended_event: event to signal termination
        :param print_output: whether to print captured output on stdout as well
        :param out_stream: stream used for output
        """
        '''The loop is terminated by the empty string sentinel when stream EOF is reached'''
        for i in iter(pipe.readline, ''):
            capture_list.append(i.rstrip('\n'))
            if print_output:
                print >> out_stream, i
        '''Stream has reached EOF, signal termination and return'''
        ended_event.set()

    @staticmethod
    def get_stream_wrapper(stream):
        """
        Internal method (used from run_subprocess implementation) to handle MultiThreadedBufferedHandler streams

        Since run_subprocess is using additional threads to monitor process output (using _get_output), any output
        would be registered in the context of the helper threads. This method returns a stream-like object that
        can be used to output messages in the context of the thread which is current when this method is called.
        This wrapper stream can be passed down to the monitoring threads such that their output is captured in the
        context of their parent. See run_process implementation
        :param stream: target stream
        :return: stream-like object that can be used to output messages in the context of this current thread
        """
        return SubprocessUtils.FixedThreadStreamWrapper(stream)

    @staticmethod
    def manage_subprocess_streams(sp, command_input=None, print_stdout=True):
        """
        Provides command input to input stream, monitors and captures out and error streams
        :param sp: subprocess instance
        :param command_input: display captured stdout content
        :param print_stdout: display the content of stdout
        :return: (captured output, captured error)
        """

        # Capture output lists
        out, err = [], []
        out_ended, err_ended = threading.Event(), threading.Event()

        # Threads for monitoring outputs
        out_stream = SubprocessUtils.get_stream_wrapper(sys.stdout)
        thread.start_new_thread(SubprocessUtils.get_output, (sp.stdout, out, out_ended, print_stdout, out_stream))
        thread.start_new_thread(SubprocessUtils.get_output, (sp.stderr, err, err_ended, False))

        if command_input:
            sp.stdin.write(command_input)
            sp.stdin.close()

        # wait for termination
        out_ended.wait()
        err_ended.wait()

        sp.wait()

        return '\n'.join(out), '\n'.join(err)

    @staticmethod
    def kill_subprocess(proc):
        """
        Forcibly terminate process
        :param proc: subprocess.Popen object
        """
        if proc is not None:
            if PLATFORM == 'Windows':
                print("Running TASKKILL for PID {0} and its siblings".format(proc.pid))
                os.system('TASKKILL /F /PID {0} /T'.format(proc.pid))

            else:
                raise Exception('Current operating system not supported: {0}'.format(PLATFORM))

    class FixedThreadStreamWrapper(object):
        """
        Wraps a stream object and provides a fixed thread-id context in case of MultiThreadedBuffered*Stream instances.
        It has no effect on regular streams
        """

        def __init__(self, stream):
            self.stream = stream
            if isinstance(stream, MultiThreadedOutput.MultiThreadedBufferedHandler.MultiThreadedBufferedOutStream) \
                    or \
                    isinstance(stream, MultiThreadedOutput.MultiThreadedBufferedHandler.MultiThreadedBufferedErrStream):
                self.thread_id = thread.get_ident()

        def write(self, message):
            if (
                isinstance(
                    self.stream, MultiThreadedOutput.MultiThreadedBufferedHandler.MultiThreadedBufferedOutStream) or
                isinstance(self.stream, MultiThreadedOutput.MultiThreadedBufferedHandler.MultiThreadedBufferedErrStream)
            ):
                return self.stream.write(message, self.thread_id)
            else:
                return self.stream.write(message)


class MultiThreadedOutput(object):
    """
    Implement redirection of standard output / error streams to organize output coming from multiple execution threads
    that would otherwise be interleaved.

    The class implements a smart buffering technique: one of the threads is designated as 'live' and its output is
    allowed to go though, while output from all the rest of the threads is internally buffered. When the live thread is
    flushed, another thread is chosen as 'live', any past output from this thread that has been buffered is emitted and
    any future output will be allowed to go through unbuffered.

    This is a context-manager type of class that can be used in 'with' constructs to enable redirection in a particular
    scope. The redirection is cancelled automatically when getting out of scope and the accumulated output is flushed
    to the original standard output organized by each contributing thread.

    A typical use of this context manager includes surrounding a block of code (which makes use of multi-threading for
    performing parallel work that generates output). When used in this way there is no need for any change in the
    existing block of code. However the entire output for all the threads will be visible only when leaving the scope.

    Minimal changes to existing code (calling flush method when a thread finishes execution) makes the overall output
    more lively by following threads which are still active.
    See SequentialOutputThreadPool class for an example that enhances the multiprocessing.dummy.Pool thread pool by
    automatically inserting a flush call whenever the task performed by a thread executor is complete.

    There is an inherent compromise when using this class, as some output is buffered until it can be presented in a
    structured way (real-time output is sacrificed for clarity). Given that there is a difference between the moment
    the output is generated and the time it is finally flushed to the output stream, it may be confusing when used in
    automated systems that timestamp incoming console messages (eg. Bamboo). To alleviate this problem, the class
    provides an option to automatically decorate the output with the time when the output has been originally recorded
    (see constructor parameter `timestamp`)
    """

    def __init__(self, timestamp=True, thread_ident=False):
        """
        Initialize the redirection and provide decoration options
        :param timestamp: `True` to prepend each received message with a time representation
        :param thread_ident: `True` to prepend each received message with a thread identifier
        """

        # Initialize logging system
        logging.basicConfig()

        # Save original streams and instantiate multi-threaded buffered streams
        self.orig_stdout = sys.stdout
        self.orig_stderr = sys.stderr
        self.mthandler = self.MultiThreadedBufferedHandler(timestamp=timestamp,
                                                           thread_ident=thread_ident,
                                                           out_stream=self.orig_stdout,
                                                           err_stream=self.orig_stderr)

        self.redirected_stdout = self.MultiThreadedBufferedHandler.MultiThreadedBufferedOutStream(self.mthandler)
        self.redirected_stderr = self.MultiThreadedBufferedHandler.MultiThreadedBufferedErrStream(self.mthandler)

    def __enter__(self):
        """ Redirect streams """

        sys.stdout = self.redirected_stdout
        sys.stderr = self.redirected_stderr
        return self

    def __exit__(self, type_, value, tb):
        """ Restore streams and flush the buffered streams """

        sys.stdout = self.orig_stdout
        sys.stderr = self.orig_stderr

        # Flush all known threads
        for tid in self.mthandler.get_threads():
            self.mthandler.flush(tid)

    def flush(self):
        self.mthandler.flush()

    class MultiThreadedBufferedHandler(object):
        """
        Utility class for handling (stdout & stderr) output from multiple threads
        The output is buffered separately according to the thread in which it originated
        """

        STDOUT = 1
        STDERR = 2

        def __init__(self, timestamp, thread_ident, out_stream, err_stream):
            """
            Initialize the buffering stream
            :param timestamp: `True` to prepend each received message with a time representation
            :param thread_ident: `True` to prepend each received message with a thread identifier
            :param out_stream: output stream used for flushing
            :param err_stream: output stream used for flushing
            """

            # Initialize a lock for managing concurrent access to data
            self.lock = threading.RLock()
            # Initialize a dictionary for managing per-thread logger instances
            self.loggers = dict()
            # The thread whose output is live
            self.live_tid = None
            # Initialize the message formatter
            fmt = '%(message)s'
            if thread_ident:
                fmt = '%(thread)s  ' + fmt
            if timestamp:
                fmt = '%(asctime)s  ' + fmt
            # Initialize a StreamHandler based on the specified stream and formatting options
            formatter = logging.Formatter(fmt, datefmt='%H:%M:%S')
            self.out_handler = logging.StreamHandler(out_stream)
            self.out_handler.setFormatter(formatter)
            self.err_handler = logging.StreamHandler(err_stream)
            self.err_handler.setFormatter(formatter)
            # Initialize a list for saving (non-live) loggers that need to be flushed at the next opportunity
            self.to_flush = []

        def do_write(self, stream_id, message, thread_id=None):
            """
            Store a message targted for steam_id as pertaining to a thread
            Called from the MultiThreadedBufferedOutStream/MultiThreadedBufferedErrStream wrappers
            :param stream_id: STDOUT / STDERR identifier
            :param message: message to be stored
            :param thread_id: `None` to use the current thread identifier, or specify a particular thread_id
            (logging in a context of another thread)
            """

            tid = thread_id or thread.get_ident()
            if tid not in self.loggers:
                with self.lock:
                    # Initialize BufferingLoggers for the new thread
                    self.loggers[tid] = {self.__class__.STDOUT: self.BufferingLogger(target=self.out_handler),
                                         self.__class__.STDERR: self.BufferingLogger(target=self.err_handler)}
                    if not self.live_tid:
                        for l in self.loggers[tid].values():
                            l.set_live()
                        self.live_tid = tid

            self.loggers[tid][stream_id].log(message)

        def get_threads(self):
            """
            Returns the list of threads that have contributed messages
            :return: list of thread identifiers
            """

            return self.loggers.keys()

        def flush(self, thread_id=None):
            """
            Flush the messages received so far to the target stream
            :param thread_id: `None` to use the current thread identifier, or specify a particular thread_id
            """

            tid = thread_id or thread.get_ident()
            with self.lock:
                if tid in self.loggers:
                    if self.live_tid == tid:
                        # The currently live thread just finished
                        # Remove its loggers (all output has gone though already)
                        self.loggers.pop(tid)

                        # Flush any other (buffering) loggers for finished non-live threads
                        for l in self.to_flush:
                            l.flush()
                        self.to_flush = []

                        # Look for another thread and make it live
                        self.live_tid = None
                        for th, d in self.loggers.iteritems():
                            self.live_tid = th
                            # Flush any existing buffered content now;
                            # any new content will go through automatically after setting it live
                            for l in d.values():
                                l.flush()
                                l.set_live()
                            break
                    else:
                        # A thread which was not live just finished
                        # Remove its loggers and save them for flushing later (when we have the chance)
                        self.to_flush.extend(self.loggers.pop(tid).values())

        class MultiThreadedBufferedOutStream(object):
            """
            Stream-like utility class for handling stdout output from multiple threads
            This is just a wrapper over MultiThreadedBufferedHandler pointing to the output stream
            """

            def __init__(self, multi_threaded_handler):
                """
                Initialize the wrapper
                :param multi_threaded_handler: instance of MultiThreadedBufferedHandler to forward to
                """
                self.mth = multi_threaded_handler

            def write(self, message, thread_id=None):
                """
                Store a message as pertaining to a thread
                :param message: message to be stored
                :param thread_id: `None` to use the current thread identifier, or specify a particular thread_id
                (logging in a context of another thread)
                """
                return self.mth.do_write(MultiThreadedOutput.MultiThreadedBufferedHandler.STDOUT, message, thread_id)

        class MultiThreadedBufferedErrStream(object):
            """
            Stream-like utility class for handling stderr output from multiple threads
            This is just a wrapper over MultiThreadedBufferedHandler pointing to the error stream
            """

            def __init__(self, multi_threaded_handler):
                """
                Initialize the wrapper
                :param multi_threaded_handler: instance of MultiThreadedBufferedHandler to forward to
                """
                self.mth = multi_threaded_handler

            def write(self, message, thread_id=None):
                """
                Store a message as pertaining to a thread
                :param message: message to be stored
                :param thread_id: `None` to use the current thread identifier, or specify a particular thread_id
                (logging in a context of another thread)
                """
                return self.mth.do_write(MultiThreadedOutput.MultiThreadedBufferedHandler.STDERR, message, thread_id)

        class BufferingLogger(object):
            """
            Utility class that provides logger-like functionality adding support for buffering and flushing

            It is implemented on top of python logging support, making use of a custom unlimited MemoryHandler
            """

            # Keep track of instances (thread-safe) so we can have unique logger names
            lock = threading.Lock()
            instance_count = 0

            def __init__(self, target):
                """
                Initialize the logger.
                :param target: target handler for when flushing this handler
                """

                with self.__class__.lock:
                    name = '{0}{1}'.format(self.__class__, self.__class__.instance_count)
                    self.__class__.instance_count += 1
                self.logger = logging.getLogger(name)
                self.logger.propagate = False
                self.logger.setLevel(logging.DEBUG)
                self.handler = self.UnlimitedHandler()
                self.handler.setLevel(logging.DEBUG)
                self.handler.setTarget(target)
                self.logger.addHandler(self.handler)

            def __del__(self):
                """
                Clean-up
                """
                self.logger.removeHandler(self.handler)

            def log(self, message):
                """
                Log a message
                """
                self.logger.info(message)

            def flush(self):
                """
                Flush the accumulated messages to the underlying target handler
                """
                self.handler.flush()

            def set_live(self):
                """
                Change this logger to live mode
                """
                self.handler.set_buffering(False)

            class UnlimitedHandler(logging.handlers.MemoryHandler):
                """
                This class overrides the MemoryHandler functionality to provide an unlimited handler that can
                work in either buffered mode (never flushes) or in live mode (always flushes)
                It is intended to be used as a logging handler
                """

                def __init__(self, buffering=True):
                    """
                    Initialize the handler
                    :param  buffering: `True` for buffering mode, `False` for live mode
                    """
                    logging.handlers.MemoryHandler.__init__(self, capacity=float("inf"))
                    self.buffering = buffering

                def set_buffering(self, buffering):
                    """
                    Set buffering behavior
                    :param  buffering: `True` for buffering mode, `False` for live mode
                    """
                    self.buffering = buffering

                def shouldFlush(self, record):
                    """
                    Return according to configured behavior
                    """
                    return not self.buffering


class SequentialOutputThreadPool(object):
    """
    Pool-like class that handles concurrent output from threads and displays it in a sequential manner
    """

    def __init__(self, processes=None, initializer=None, initargs=()):
        self.pool = ThreadPool(processes, initializer, initargs)

    @staticmethod
    def _wrapper(args):
        """
        Wrapper over client provided func & iterable arguments which takes care of flushing output when the work is done
        :param args: tuple crafted inside map method
        :return: result of performing the work
        """
        arg, func, mto = args
        try:
            result = func(arg)
        finally:
            mto.flush()
        return result

    def map(self, func, iterable, chunksize=1):
        """
        Equivalent of `map()` method in Pool
        """
        with MultiThreadedOutput() as mto:
            # Wrap whatever is provided by clients along with func and mto references in a tuple
            # and pass it to the wrapper method
            targets = itertools.izip(iterable, itertools.repeat(func), itertools.repeat(mto))
            results = self.pool.map(SequentialOutputThreadPool._wrapper, targets, chunksize)
            self.pool.close()
            self.pool.join()
            return results


# Save original shutil methods
shutil_copy = shutil.copy
shutil_copy2 = shutil.copy2
shutil_move = shutil.move
shutil_copytree = shutil.copytree
shutil_rmtree = shutil.rmtree


class ShutilWrappers(object):
    """
    Wrappers over shutil methods to avoid the MAX_PATH 260 characters limit in Win32 API '''
    """

    @staticmethod
    def _path(path):
        """ Internal method used to format paths with '\\\\?\\' prefix that bypasses normal path processing """
        return (
            path if path.startswith('\\\\') or not os.path.isabs(path)
            else u'\\'.join([u'\\\\?', path.replace('/', '\\')])
        )

    @staticmethod
    def _copy_wrapper(src, dst):
        """ Wrapper over shutil.copy which takes care of path arguments """
        return shutil_copy(ShutilWrappers._path(src), ShutilWrappers._path(dst))

    @staticmethod
    def _copy2_wrapper(src, dst):
        """ Wrapper over shutil.copy2 which takes care of path arguments """
        return shutil_copy2(ShutilWrappers._path(src), ShutilWrappers._path(dst))

    @staticmethod
    def _move_wrapper(src, dst):
        """ Wrapper over shutil.move which takes care of path arguments """
        return shutil_move(ShutilWrappers._path(src), ShutilWrappers._path(dst))

    @staticmethod
    def _copytree_wrapper(src, dst, symlinks=False, ignore=None):
        """ Wrapper over shutil.copytree which takes care of path arguments """
        return shutil_copytree(ShutilWrappers._path(src), ShutilWrappers._path(dst), symlinks, ignore)

    @staticmethod
    def _rmtree_wrapper(path, ignore_errors=False, onerror=None):
        """ Wrapper over shutil.rmtree which takes care of path arguments """
        return shutil_rmtree(ShutilWrappers._path(path), ignore_errors, onerror)

    @staticmethod
    def install_shutil_wrappers():
        """
        Replace shutil methods with wrappers that can handle long paths
        The problem is limited to Windows platform
        """
        if PLATFORM == 'Windows':
            shutil.copy = ShutilWrappers._copy_wrapper
            shutil.copy2 = ShutilWrappers._copy2_wrapper
            shutil.move = ShutilWrappers._move_wrapper
            shutil.copytree = ShutilWrappers._copytree_wrapper
            shutil.rmtree = ShutilWrappers._rmtree_wrapper


class PowerResetUtils(object):
    """
    Interface for hardware devices reset
    Subclasses need only to provide enough info for the functions they use
    """
    def __init__(self):
        pass

    def clear_line(self, line):
        """
         "Do not call using an instance of this class. Must be overridden in derived classes."
        """
        raise NotImplementedError('Cannot call method {0} of abstract class {1} instance'
                                  .format(inspect.currentframe().f_code.co_name, self.__class__.__name__))

    def set_line(self, line):
        """
         "Do not call using an instance of this class. Must be overridden in derived classes."
        """
        raise NotImplementedError('Cannot call method {0} of abstract class {1} instance'
                                  .format(inspect.currentframe().f_code.co_name, self.__class__.__name__))

    def reset_line(self, line):
        """
         "Do not call using an instance of this class. Must be overridden in derived classes."
        """
        raise NotImplementedError('Cannot call method {0} of abstract class {1} instance'
                                  .format(inspect.currentframe().f_code.co_name, self.__class__.__name__))

    def read_line(self, line):
        """
         "Do not call using an instance of this class. Must be overridden in derived classes."
        """
        raise NotImplementedError('Cannot call method {0} of abstract class {1} instance'
                                  .format(inspect.currentframe().f_code.co_name, self.__class__.__name__))

    @staticmethod
    def get_instance(class_name, config):
        """
        Creates an instance of a class based on its name. The name is expected to be given as module.class
        :param class_name: Class name in the form of module.class
        :param config: dictionary used for class configuration
        :return: An instance of the class
        """
        return Utils.get_instance_from_name(class_name, config)

    @staticmethod
    def reset_resource(resource):
        """
        Resets a resource (e.g. a device)
        - if the resource has a reset_device attribute (i.e. the device is connected to a reset device), then the
          resource is reset
        - if the resource does not have a reset_device attribute, do nothing
        :param: resource:  A resource as defined in the helper//resources.xml
        """
        if 'reset_device' in resource:
            with ResourceManager().get_resource({'key': resource['reset_device'],
                                                 'type': 'reset_device'}) as reset_config:
                power_line = int(resource['reset_line'])
                PowerResetUtils().get_instance(reset_config['class'], reset_config).reset_line(power_line)


class ModbusTCPResetUtils(PowerResetUtils):
    """
    Helper class designed to turn on/off hardware devices using ADAM5000 TCP devices
    """
    def __init__(self, configuration):
        self.configuration = configuration
        self.connection = ModbusClient(host=self.configuration['reset_device_ip'],
                                       port=int(self.configuration['port']))
        if not self.connection.open():
            raise Exception('Selected reset device is unreachable {0}'.format(self.configuration['reset_device_ip']))

    def clear_line(self, line):
        """
        Clears the selected power line, equivalent of switching the power supply off.
        Returns: True if operation was successful, exception otherwise.
        """
        self.check_line(line)
        self.connection.write_single_coil(line, False)
        if self.read_line(line):
            raise Exception('Clear line operation has failed. Please check connection.')
        return True

    def set_line(self, line):
        """
        Sets the selected power line, equivalent of switching the power supply on.
        Returns: True if operation was successful, exception otherwise.
        """
        self.check_line(line)
        self.connection.write_single_coil(line, True)
        if not self.read_line(line):
            raise Exception('Set line operation has failed. Please check connection.')
        return True

    def reset_line(self, line):
        """
        Clears the selected power line, equivalent of switching the supply off, waits for two seconds and sets it on
        again. Equivalent of a hardware reset.
        Returns: True if operation was successful, exception otherwise.
        """
        self.clear_line(line)
        'Wait for three seconds to make sure that all capacitors are not loaded anymore'
        sleep(int(self.configuration['delay_time']))
        self.set_line(line)
        print 'Device reset operation has been successful'

    def read_line(self, line):
        """
        Returns: Value read from selected power line, True if open, False if closed.
        """
        self.check_line(line)
        return self.connection.read_coils(line)[0]

    def check_line(self, line):
        """
        Returns: True if selected power line is among the available lines, listed in resources.xml, exception if not.
        """
        available_power_lines = map(int, list(self.configuration['available_power_lines'].replace(' ', '').split(',')))
        if line not in available_power_lines:
            raise Exception('Selected line for operation: {0} is not available. Available lines: {1}'.
                            format(line, self.configuration['available_power_lines']))
        return True


class ThreadingLockManager(object):
    """Class which implements a locking mechanism based on a given hash value and corresponding lock created for it.
     A hash could be any unique value that defines the place where the lock should take action (a line number, a hashed
     function name, file name, etc).
    """

    def __init__(self, lock, lock_id):
        self.__lock = lock
        self.__lock_id = lock_id

    def acquire_lock(self, timeout=None):
        """Grab a lock and execute a task.
        :param timeout: The optional timeout argument
        :return: The LockResource manager object
        """

        if not self.__lock.acquire(timeout=timeout):
            raise ThreadingLockError('Could not acquire lock during the allocated time frame, we will exit now!')

        return ThreadingLockManager.LockResource(self.__lock, self.__lock_id)

    class LockResource(object):
        """Implements a locking mechanism using a context manager."""

        def __init__(self, lock, lock_id):
            if not isinstance(lock, ThreadingLock):
                raise ThreadingLockError('Wrong object type passed to constructor, it should be a ThreadingLock object')

            self.__lock = lock
            self.lock_id = lock_id

        def __enter__(self):
            """Returns the context manager object.
            :return The context manager object
            """

            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            """Tries to release the lock.
            :return None
            """

            if exc_type:
                raise Exception('An exception occurred while lock has been acquired for id {0}: {1}'.format(
                    self.lock_id, ''.join(format_exception(exc_type, exc_val, exc_tb))
                ))

            # Consecutive calls to release should not happen, however they will be handled
            try:
                self.__lock.release()
            except threading.ThreadError:
                exc_type, exc_val, exc_tb = sys.exc_info()
                print('An exception occurred while trying to release a lock:{0}{1}'.format(
                    os.linesep, format_exception(exc_type, exc_val, exc_tb)[-1]
                ))


class ExceptionUtils(object):
    """
    Class containing general exception utils methods
    """

    def __init__(self):
        pass

    @staticmethod
    def print_exception_message():
        """Do not exit in case a command fails.
        Just print the failure message.
        """
        ext_type, exc_value, exc_traceback = sys.exc_info()
        print exc_value


class RegistryUtils(object):
    """Class containing windows registry utils."""

    @staticmethod
    def delete_key(root, parent_key, pattern, case_insensitive=False, verbose=True):
        """
        Deletes a registry key if it matches the given pattern.
        :param root: an already open key, or any one of the predefined HKEY_* constants:
                    winreg.HKEY_CLASSES_ROOT
                    winreg.HKEY_CURRENT_USER
                    winreg.HKEY_LOCAL_MACHINE
                    winreg.HKEY_USERS
                    winreg.HKEY_PERFORMANCE_DATA
                    winreg.HKEY_CURRENT_CONFIG
                    winreg.HKEY_DYN_DATA
        :param parent_key: a string that identifies the sub_key to open.
        :param pattern: regular expression that will be used to find the target key to be deleted.
        :param case_insensitive: specify whether the pattern will be case insensitive. Default is False.
        :param verbose: if True print which keys are deleted.
        """
        if case_insensitive:
            flags = re.IGNORECASE
        else:
            flags = 0

        try:
            with winreg.OpenKey(root, parent_key, 0, winreg.KEY_ALL_ACCESS) as key:
                total_subkeys, _, _ = winreg.QueryInfoKey(key)

                key_index = 0
                while total_subkeys > 0:
                    subkey = winreg.EnumKey(key, key_index)
                    if re.search(pattern, subkey, flags):
                        if verbose:
                            print(r"Deleting registry key: {key}\{subkey}.".format(key=parent_key, subkey=subkey))
                        winreg.DeleteKey(key, subkey)
                        total_subkeys -= 1
                    else:
                        key_index += 1
                    if key_index == total_subkeys:
                        break
        except WindowsError:
            if verbose:
                print("Could not open key {parent_key}.".format(parent_key=parent_key))
            return
