#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
shared_drive_mounting_utils.py: This module contains tools related to mounting shared drives under Windows.
"""


import os
import subprocess


class SharedDriveMountingUtils(object):
    """Network drive mounting info."""

    DRIVE_PATH = 'Z:'
    SHARED_DRIVE_SHORT_PATH = r'\\zroproj01'
    SHARED_DRIVE_PATH = r'\\zroproj01.ea.freescale.net'
    PROCESSOR_EXPERT_AUTO_MOUNT_PATH = r'\\zroproj01.ea.freescale.net\ProcessorExpertAuto'
    LINUX_MOUNT_PATH = '/media/autobuild/'

    def __init__(self, drive_path=None, shared_drive_path=None):
        """CTOR.
        :param drive_path: Drive path where to mount network shared drive [str]
        :param shared_drive_path: Full path to the shared drive to mount [str]
        """
        self.__drive_path = drive_path
        self.__shared_drive_path = shared_drive_path

    @property
    def drive_path(self):
        """Getter for <drive_path>."""
        return self.__drive_path

    @property
    def shared_drive_path(self):
        """Getter for <shared_drive_path>."""
        return self.__shared_drive_path

    def check_and_mount_shared_drive(
            self, drive_path=None, shared_drive_path=None, force_unmap=False, use_shell_cmds=False, verbose=False
    ):
        """Check if the shared drive is mounted or not. If not => mount it. Method works only under WINDOWS OS.
        :param drive_path: Drive path where to mount network shared drive [str]
        :param shared_drive_path: Full path to the shared drive to mount [str]
        :param force_unmap: Force the drive to unmap [bool]
        :param use_shell_cmds: Execute (un)mount operations by using SHELL cmds [bool]
        :param verbose: Get verbose about the output [bool]
        """
        if not shared_drive_path:
            shared_drive_path = self.shared_drive_path
            if not shared_drive_path:
                print("{line_sep}No network shared drive path supplied!{line_sep}".format(line_sep=os.linesep))
                return

        if not drive_path:
            drive_path = self.drive_path
            if not self.drive_path:
                print("{line_sep}No drive path supplied!{line_sep}".format(line_sep=os.linesep))
                return

        if not force_unmap and os.path.exists(drive_path):
            print(
                "{line_sep}Drive '{drive_path}' is in use! Do not try to unmap and map again!{line_sep}".format(
                    line_sep=os.linesep, drive_path=drive_path)
            )
            return True

        if use_shell_cmds:
            if force_unmap:
                # Disconnect anything on <shared_drive_path>
                cmd_to_run = r'net use /DELETE {drive_path}'.format(drive_path=drive_path)
                if verbose:
                    print("Executing command: {cmd_to_run}".format(cmd_to_run=cmd_to_run))
                subprocess.call(cmd_to_run, shell=True)

            # Connect to shared drive, use drive letter Z
            cmd_to_run = r'net use {drive_path} {shared_drive_path}'.format(
                drive_path=drive_path, shared_drive_path=shared_drive_path
            )
            if verbose:
                print("Executing command: {cmd_to_run}".format(cmd_to_run=cmd_to_run))
            subprocess.call(cmd_to_run, shell=True)

            if not os.path.exists(drive_path):
                raise ValueError(
                    "{line_sep}Map operation failed for drive '{drive_path}'. "
                    "This might not be a network drive...{line_sep}".format(line_sep=os.linesep, drive_path=drive_path)
                )

            return True

        import pywintypes
        from win32netcon import RESOURCETYPE_DISK
        from win32wnet import WNetAddConnection2, WNetCancelConnection2

        if os.path.exists(drive_path):
            if force_unmap:
                print(
                    "{line_sep}Drive '{drive_path}' in use, trying to unmap ...{line_sep}".format(line_sep=os.linesep,
                                                                                                  drive_path=drive_path)
                )
                try:
                    WNetCancelConnection2(drive_path, 1, 1)
                    print("{line_sep}Successfully unmapped ...{line_sep}".format(line_sep=os.linesep))
                except pywintypes.error as err:
                    print(
                        "{line_sep}Unmap failed for drive '{drive_path}'. "
                        "This might not be a network drive...{line_sep}{err}{line_sep}".format(
                            line_sep=os.linesep, drive_path=drive_path, err=err)
                    )
            else:
                print("{line_sep}Non-forcing call. Will not unmap ...{line_sep}".format(line_sep=os.linesep))
        else:
            print(
                "{line_sep}Drive '{drive_path}' is free ...{line_sep}".format(line_sep=os.linesep,
                                                                              drive_path=drive_path)
            )

        if not os.path.exists(shared_drive_path):
            raise ValueError(
                "{line_sep}Network path '{shared_drive_path}' unreachable ...{line_sep}".format(
                    line_sep=os.linesep,
                    shared_drive_path=shared_drive_path)
            )

        print(
            "{line_sep}Shared drive '{shared_drive_path}' was found ...{line_sep}"
            "Trying to map '{shared_drive_path}' on to '{drive_path}' ...{line_sep}".format(
                line_sep=os.linesep,
                shared_drive_path=shared_drive_path,
                drive_path=drive_path)
        )
        try:
            WNetAddConnection2(RESOURCETYPE_DISK, drive_path, shared_drive_path, None)
        except pywintypes.error as err:
            raise ValueError(
                "{line_sep}Mapping failed for drive '{drive_path}'.{line_sep}{err}{line_sep}".format(
                    line_sep=os.linesep, drive_path=drive_path, err=err)
            )

        print("{line_sep}Mapping successful!{line_sep}".format(line_sep=os.linesep))
        return True

    def umount_shared_drive(self, drive_path=None, verbose=False):
        """Disconnect specified drive path.
        :param drive_path: Drive path to disconnect from Windows OS [str]
        :param verbose: Get verbose about the output [bool]
        """
        if not drive_path:
            drive_path = self.drive_path
            if not drive_path:
                print("{line_sep}No drive path supplied!{line_sep}".format(line_sep=os.linesep))
                return

        if not os.path.exists(drive_path):
            print(
                "{line_sep}Drive path '{drive_path}' does not exist{line_sep}".format(
                    line_sep=os.linesep, drive_path=drive_path)
            )
            return False

        cmd_to_run = r'net use /DELETE {drive_path}'.format(drive_path=drive_path)
        if verbose:
            print("Executing command: {cmd_to_run}".format(cmd_to_run=cmd_to_run))
        subprocess.call(cmd_to_run, shell=True)

        if os.path.exists(drive_path):
            raise ValueError(
                "{line_sep}Unmap failed for drive path '{drive_path}'. "
                "This might not be a network drive...{line_sep}".format(line_sep=os.linesep, drive_path=drive_path)
            )

        return True
