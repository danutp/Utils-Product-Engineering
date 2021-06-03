import os

from nxp.utilsNG.helper.utils import Utils


class GitUtils:
    """
    Wrapper over git operations (clone, checkout, ...)
    """
    def __init__(self):
        pass

    '''Default server URL'''
    DEFAULT_SERVER = 'bitbucket.sw.nxp.com'

    # RO mirror server URL
    RO_MIRROR_SERVER = 'bitm-ro-buh01.sw.nxp.com:7999/bitbucket'

    class AccessProtocol:
        """
        Encapsulated the access protocols to a server
        """
        def __init__(self):
            pass

        HTTP = 'http'
        HTTPS = 'https'
        SSH = 'ssh'

    @staticmethod
    def run_git(arguments, cwd=None, kill_after_timeout=-1,
                wait_for_process_end=True, return_when_error=False):
        """
        Execute git command with process specific parameters. May be extended to other parameters specified in
        run_subprocess method.
        :param arguments: The arguments to the git command
        :param cwd: Run as if git was started in the given path instead of the current working directory.
                        Default is "", which means the current working directory is left unchanged.
        :param kill_after_timeout: The timeout period after the process is killed
        :param wait_for_process_end: Specifies whether the caller should wait for the process to finish
        :param return_when_error: Return the Popen object, the output and error even on failure
        :returns The sp_object, output, error tuple
        """

        return Utils.run_subprocess(
            'git -C "{working_dir}" {args}'.format(working_dir=cwd or "", args=arguments),
            kill_after_timeout=kill_after_timeout,
            wait_for_process_end=wait_for_process_end,
            return_when_error=return_when_error
        )

    @staticmethod
    def clone(uri, path, recurse_submodules=False):
        """
        Clone from Git repo uri (its default branch content) to a given location in the form of a path.
        If the paths exists, its content is wiped out, otherwise the path is created. Path must be a folder.
        :param uri: uri to the repo to be cloned
        :param path: Path where to clone the repo content
        :param recurse_submodules: initialize and update each submodule in the repository,
                                   including nested submodules if any of the submodules in
                                   the repository have submodules themselves.
        """
        if os.path.exists(path):
            if not os.path.isdir(path):
                raise Exception('Path where to clone a git repo must be folder: {0}'.format(path))
            else:
                Utils.delete_dir_content(path)
        else:
            os.makedirs(path)

        recurse_submodules_cmd = "--recurse-submodules" if recurse_submodules else ""

        GitUtils.run_git('clone {0} {1} {2}'.format(recurse_submodules_cmd, uri, path))

    @staticmethod
    def submodule(command, options=None, path=None, cwd=None, kill_after_timeout=-1, wait_for_process_end=True,
                  return_when_error=False):
        """
        Initiates, updates or takes any other submodule available action for the current repository.
        :param command: A submodule available command (init, update, status, etc.)
        :param options: A submodule option list, as string
        :param path: The optional path parameter
        :param cwd: Run as if git was started in the given path instead of the current working directory.
                    Default is "", which means the current working directory is left unchanged.
        :param kill_after_timeout: The timeout period after the process is killed
        :param wait_for_process_end: Specifies whether the caller should wait for the process to finish
        :param return_when_error: Return the Popen object, the output and error even on failure
        :returns The sp_object, output, error tuple
        """

        return GitUtils.run_git(
            'submodule {0} {1} {2}'.format(command, options or "", path or ""),
            cwd=cwd,
            kill_after_timeout=kill_after_timeout,
            wait_for_process_end=wait_for_process_end,
            return_when_error=return_when_error
        )

    @staticmethod
    def checkout(branch):
        """
        Checkout a branch. Assumes the current working dir contains a git repo (i.e. a cloned one)
        :param branch: Branch to checkout from
        """
        GitUtils.run_git('checkout {0}'.format(branch))

    @staticmethod
    def clone_bitbucket_repo(project, repo, path, protocol=AccessProtocol.SSH, server=DEFAULT_SERVER):
        """
        Clone the content of a Bitbucket repo (its default branch content) identified by project and repo name.
        A project can contain multiple repos
        :param protocol: server access protocol (can be HTTP, HTTPS or SSH)
        :param server: Bitbucket server
        :param project: project name
        :param repo: repo name
        :param path: Path where to clone the repo content
        """
        GitUtils.clone('{0}://git@{1}/{2}/{3}.git'.format(protocol, server, project, repo), path)

    @staticmethod
    def checkout_bitbucket_branch(project, repo, branch_tag_sha, path, protocol=AccessProtocol.SSH, server=DEFAULT_SERVER):
        """
        Checks out a branch from a Bitbucket project/repo into a given path.
        :param protocol: server access protocol (can be HTTP, HTTPS or SSH)
        :param server: Bitbucket server
        :param project: project name
        :param repo: repo name
        :param branch_tag_sha: branch or tag or sha to chekout from
        :param path: Path where to checkout the branch content
        """
        GitUtils.clone_bitbucket_repo(project=project, repo=repo, path=path, protocol=protocol, server=server)
        os.chdir(path)
        GitUtils.checkout(branch_tag_sha)

    @staticmethod
    def alternative_clone_git_repo(repo_ssh, checkout_directory, repo_branch, repo_custom_revision=None, depth=None):
        """Alternative method for cloning git repo. Uses a depth parameter to restrict the commit history checkout.
        :param repo_ssh: uri to the repo to be cloned
        :param checkout_directory: name of folder where you perform the checkout
        :param repo_branch: name of the repo branch to be cloned
        :param repo_custom_revision: custom revision in long format(40 digits)
        :param depth: restrict the commit history checkout.
        """
        if repo_custom_revision and len(repo_custom_revision) != 40:
            raise Exception('Please use custom revision in long format. It should have 40 digits!')

        origin = repo_custom_revision if repo_custom_revision else repo_branch
        depth_arg = ' --depth {}'.format(int(depth)) if depth else ''

        commands = [
            'mkdir {0}'.format(checkout_directory),
            'cd {0}'.format(checkout_directory),
            'git init',
            'git remote add origin {0}'.format(repo_ssh),
            'git fetch origin {0}{1}'.format(origin, depth_arg),
            'git reset --hard FETCH_HEAD',
            'cd ..'
        ]

        Utils.run_subprocess(' && '.join(commands))

    @staticmethod
    def set_autocrlf(value):
        """Set autocrlf value for Git
        https://git-scm.com/book/en/v2/Customizing-Git-Git-Configuration#_code_core_autocrlf_code
        :param value: value of the 'autocrlf' flag
        """

        set_autocrlf_cmd = 'git config --global core.autocrlf {0}'.format('true' if value else 'false')
        try:
            set_status = Utils.run_subprocess(set_autocrlf_cmd)[0]
        except Exception as err:
            print('\nFailed executing command:\n\t[{0}]\n\t{1}\n'.format(set_autocrlf_cmd, err))
            return

        if set_status.returncode != 0:
            msg = 'Failed executing command:\n\t[{}]\n'.format(set_autocrlf_cmd)
            raise ValueError(msg)

        print('\nSuccessfully executed command:\n\t[{}]\n'.format(set_autocrlf_cmd))

    @staticmethod
    def execute_http_sslverify_cmd(http_sslverify_cmd):
        """(Un)set 'http.sslverify' value for Git (OS globally set)
        :param http_sslverify_cmd: Command to execute [string]
        """

        try:
            status, _, _ = Utils.run_subprocess(http_sslverify_cmd)
        except Exception as err:
            print(
                '{line_sep}Failed executing command:'
                '{line_sep}\t[{cmd}]'
                '{line_sep}\t{err}{line_sep}'.format(line_sep=os.linesep, cmd=http_sslverify_cmd, err=err)
            )
            return

        if status.returncode != 0:
            raise ValueError(
                'Failed executing command:'
                '{line_sep}\t[{cmd}]{line_sep}'.format(line_sep=os.linesep, cmd=http_sslverify_cmd)
            )

        print(
            '{line_sep}Successfully executed command:'
            '{line_sep}\t[{cmd}]{line_sep}'.format(line_sep=os.linesep, cmd=http_sslverify_cmd)
        )

    @staticmethod
    def execute_core_filemode_cmd(core_filemode_cmd):
        """(Un)set 'core.filemode' value for Git (OS globally set)
        :param core_filemode_cmd: Command to execute [string]
        """

        try:
            status, _, _ = Utils.run_subprocess(core_filemode_cmd)
        except Exception as err:
            print(
                '{line_sep}Failed executing command:'
                '{line_sep}\t[{cmd}]'
                '{line_sep}\t{err}{line_sep}'.format(line_sep=os.linesep, cmd=core_filemode_cmd, err=err)
            )
            return

        if status.returncode != 0:
            raise ValueError(
                'Failed executing command:'
                '{line_sep}\t[{cmd}]{line_sep}'.format(line_sep=os.linesep, cmd=core_filemode_cmd)
            )

        print(
            '{line_sep}Successfully executed command:'
            '{line_sep}\t[{cmd}]{line_sep}'.format(line_sep=os.linesep, cmd=core_filemode_cmd)
        )

    def set_http_sslverify(self, value=True):
        """Set 'http.sslverify' value for Git (OS globally set)
        :param value: Value to set, True/False
        """

        set_http_sslverify_cmd = 'git config --global http.sslverify {0}'.format('true' if value else 'false')
        self.execute_http_sslverify_cmd(set_http_sslverify_cmd)

    def unset_http_sslverify(self):
        """Unset 'http.sslverify' value for Git (OS globally set)"""
        unset_http_sslverify_cmd = 'git config --global --unset http.sslverify'
        self.execute_http_sslverify_cmd(unset_http_sslverify_cmd)

    def set_core_filemode(self, value=False):
        """Set 'core.filemode' value for Git (OS globally set)
        :param value: Value to set, True/False
        """
        set_core_filemode_cmd = 'git config --global core.filemode {0}'.format('true' if value else 'false')
        self.execute_core_filemode_cmd(set_core_filemode_cmd)

    def unset_core_filemode(self):
        """Unset 'core.filemode' value for Git (OS globally set)"""
        unset_core_filemode_cmd = 'git config --global --unset core.filemode'
        self.execute_core_filemode_cmd(unset_core_filemode_cmd)
