#!/usr/bin/python

import os

from helper.utils import Utils
from multiprocessing import cpu_count


__copyright__ = "2019 NXP Semiconductors."


class GoogleRepoUtils(object):
    """Google REPO utils"""

    def __init__(self):
        # os.path.expanduser("~") = Path to user home directory
        self.__repo_tool_path = Utils.get_env(
            'repo_exec', default_value=os.path.join(os.path.expanduser("~"), "bin", "repo")
        )
        # Default partition
        self.__default_partition = "D:"

    @property
    def repo_tool_path(self):
        return self.__repo_tool_path

    @property
    def default_partition(self):
        return self.__default_partition

    def repo_init(self, partition=None, working_dir=None, repo_url=None, repo_branch=None,
                  manifest_name=None, no_clone_bundle=False, depth=None):
        """Perform repo init on a repo using the manifest specified by 'manifest_name'

        :param partition: Partition where to perform 'repo init' [string]
        :param working_dir: Platform directory layout [string]
        :param repo_url: Repo URL [string]
        :param repo_branch: Repo branch [string]
        :param manifest_name: Name of the XML manifest [string]
        :param no_clone_bundle: True/False. Default is False [boolean]
               Info: disables the bundle files
        :param depth: Reduce the size of commit history [integer]

        :return: False, wrong input
        """

        if not working_dir or not repo_url or not repo_branch or not manifest_name:
            return False

        print("INFO: Start repo init... ")

        # Set partition
        partition = partition or self.default_partition

        if not os.path.isdir(working_dir):
            os.makedirs(working_dir)

        # Compound the command
        repo_init_cmd = (
            '{partition} && cd {destination} && {repo_tool_path} init -u {repo_uri} -b {branch} -m {manifest}'.format(
                partition=partition,
                destination=working_dir,
                repo_tool_path=self.repo_tool_path,
                repo_uri=repo_url,
                branch=repo_branch,
                manifest=manifest_name
            )
        )
        if no_clone_bundle:
            repo_init_cmd = repo_init_cmd + ' --no-clone-bundle'
        if depth:
            repo_init_cmd = repo_init_cmd + ' --depth={}'.format(int(depth))

        # Run command
        Utils.run_subprocess(repo_init_cmd)

    def repo_sync(self, partition=None, destination=None, to_sync=None, driver_layout=None,
                  jobs_no=None, current_branch=False, test_lfs=False, modules_for_lfs_pull=(),
                  preserve_errors=False, debug=False):
        """Perform repo sync command

        :param partition: Disk partition to use for destination dir (e.g.: "B:")
        :param destination: Checkout repo in this path (sources folder) [string]
        :param to_sync: List to sync [string]
        :param driver_layout: Path to driver parent dir [string]
        :param jobs_no: Number of projects to fetch simultaneously [integer]
        :param current_branch: Fetch only current branch from server[boolean]
        :param test_lfs: True/False [boolean]
               Perform 'git lfs ls-files --debug && git lfs pull'
        :param modules_for_lfs_pull: List of modules to perform PULL from GIT using LFS [tuple]
        :param preserve_errors: Flag used to indicate whether or not to return the STDERR as a list [boolean]
        :param debug: True/False [boolean]

        :raise ValueError, if no driver layout
        """

        if test_lfs and not driver_layout:
            raise ValueError("No driver layout supplied in order to test GIT LFS!")

        # Proper format 'to_sync'
        to_sync = " {to_sync}".format(to_sync=to_sync) if to_sync else ""

        # Set '--current_branch'
        current_branch = ' --current-branch' if current_branch else ''
        # Set '--jobs=<>'
        jobs_no = jobs_no or '{0}'.format(cpu_count())
        jobs_no = " --jobs={no}".format(no=jobs_no)
        if debug:
            jobs_no = ""

        # Set partition
        partition = partition or self.default_partition

        # Get full 'repo sync' command
        repo_sync_command = (
            '{0} && cd {1} && {2} sync{3}{4}{5}'.format(partition,
                                                        destination,
                                                        self.repo_tool_path,
                                                        jobs_no,
                                                        current_branch,
                                                        to_sync)
        )

        print(
            "{line_sep}REPO Sync command"
            "{line_sep}\t{cmd}{line_sep}".format(line_sep=os.linesep, cmd=repo_sync_command)
        )

        if not preserve_errors:
            Utils.run_subprocess(repo_sync_command)
        else:
            # STD_ERR file used to keep track of 'repo sync' errors
            stderr_file = os.path.join(destination, "std_err")
            try:
                Utils.run_subprocess(repo_sync_command, stderr_file=stderr_file)
            except Exception as err:
                try:
                    with open(stderr_file, 'r') as fd_in:
                        stderr_file_content_dump_list = [line.strip("\n") for line in fd_in]
                except Exception as file_err:
                    print(
                        "{line_sep}Error encountered when trying to read file: 'file'"
                        "{line_sep}{err}{line_sep}".format(line_sep=os.linesep, file=stderr_file, err=file_err)
                    )
                    raise ValueError(err)

                raise ValueError({'dumpStdErrFile': stderr_file_content_dump_list})

        # Test GIT LFS
        #
        # Show all LFS files from driver repo and perform pull operation on them
        # <git lfs ls-files --name-only>: only works with GIT >= v 2.20
        #
        # If GIT LFS is not supported on repo, the command will exit normally, returning 0 as error code
        if not test_lfs:
            return

        for module in modules_for_lfs_pull:
            Utils.run_subprocess(
                "{0} && cd {1} && git lfs ls-files --debug && git lfs pull".format(
                    partition, os.path.join(destination, driver_layout, module.strip())
                )
            )
