"""Module containing automation framework specific exceptions"""

__copyright__ = "Copyright 2020 NXP"

import os


class TagBasedInstallerError(Exception):
    """Base exception class for errors related to tag processing in automated (tag triggered) installers. Class might be
    extended with other necessary methods (file logging, exception parsing) that may be called in __init__"""

    def __init__(self, message):

        super(TagBasedInstallerError, self).__init__(message)


class NoTagDetectedError(TagBasedInstallerError):
    """Thrown when there is not tag detected in an automated (tag triggered) build."""

    def __init__(self, revision_number):
        """
        :param revision_number: The current commit id
        """

        self.message = 'No tag detected for revision number {0!r}. The build process will stop now.'.format(
            revision_number
        )
        super(NoTagDetectedError, self).__init__(self.message)


class TagMismatchError(TagBasedInstallerError):
    """Thrown when the tags detected in an automated (tag triggered) build do not match the requirements."""

    def __init__(self, tags):
        """
        :param tags: The current provided tags (list)
        """

        self.message = (
            'None of the tags {0!r} match the required pattern for a release. The build process will stop now.'.format(
                ', '.join(tags)
            )
        )
        super(TagMismatchError, self).__init__(self.message)


class SubmoduleInitCallError(Exception):
    """Thrown when the transition sequence NOT_EXECUTED->(EXECUTION_SUCCEEDED, EXECUTION_FAILED) is not followed
    (i.e. NOT_EXECUTED must be followed by EXECUTION_SUCCEEDED / EXECUTION_FAILED and
    EXECUTION_SUCCEEDED / EXECUTION_FAILED may only follow NOT_EXECUTED state."""

    def __init__(self, current_state, next_state):
        """
        :param current_state: The current execution state
        :param next_state: The requested execution state
        """

        self.message = 'Cannot enter {1!r} state after {0!r} state'.format(current_state, next_state)
        super(SubmoduleInitCallError, self).__init__(self.message)


class ThreadingLockError(Exception):
    """Thrown when a ThreadingLock related action fails."""

    def __init__(self, message):
        """
        :param message:  The exception message
        """

        self.message = message
        super(ThreadingLockError, self).__init__(self.message)


class FileNotFoundError(Exception):
    """Thrown when a specific required file is not found."""

    def __init__(self, not_found_file, directory=None):
        """
        :param not_found_file: The name of the file not found
        :param directory: The directory that the file has been looked up into
        """

        self.message = (
            '{0!r} file not found in directory {1!r}!'.format(self.not_found_file, self.directory) if self.directory
            else '{0!r} file not found!'.format(self.not_found_file)
        )
        self.not_found_file = not_found_file
        self.directory = directory
        super(FileNotFoundError, self).__init__(self.message)


class ResourceError(Exception):
    """
    Base class for exceptions raised when trying to get exclusive access to a resource. Besides the message from
    the derived class it takes a list of resources as dictionaries. Class might be extended with other necessary
    methods (file logging, exception parsing) that may be called in __init__
    """

    def __init__(self, resources):
        """
        :param resources: The list of resources that the caller failed to acquire
        """

        self.resources = resources

        if not self.message:
            self.message = (
                'An error occurred while trying to perform a task using the following resources{0}{1}'.format(
                    os.linesep, os.linesep.join([resource.stringify() for resource in self.resources])
                )
            )

        super(ResourceError, self).__init__(self.message)


class AcquireResourceTimeoutError(ResourceError):
    """Thrown when acquiring a resource has timed out."""

    def __init__(self, timeout, resources):
        """
        :param timeout: Timeout period (in seconds) for acquiring the lock
        :param resources: The list of resources that the caller failed to acquire
        """

        self.message = (
            'Could not acquire a resource within the provided time frame ({0} seconds/resource, {1} seconds '
            'overall wait time). Requested resources:{2}{3}'.format(
                timeout, timeout * len(resources), os.linesep, os.linesep.join(
                    [resource.stringify() for resource in self.resources]
                )
            )
        )

        super(AcquireResourceTimeoutError, self).__init__(resources)


class CoverityError(Exception):
    """Thrown when a Coverity related exception is raised"""

    def __init__(self, message):
        """
        :param message: The error message
        """

        self.message = message

        super(CoverityError, self).__init__(self.message)


class CoverityTimeoutError(CoverityError):
    """Thrown when an operation timeout occurs"""

    def __init__(self, timeout, resource_id, resource_type):
        """
        :param timeout: The timeout that has been reached while trying to lock a resource
        :param resource_id: The resource id
        :param resource_type: The resource type
        """

        self.message = (
            'Failed to acquire a lock for resource {resource_id} and type {resource_type} within '
            '{timeout} seconds'.format(resource_id=resource_id, resource_type=resource_type, timeout=timeout)
        )

        super(CoverityTimeoutError, self).__init__(self.message)


class CoveritySyncError(CoverityError):
    """Thrown when a timeout occurs in synchronization between subscriber and coordinator"""

    def __init__(self, timeout):
        """
        :param timeout: The synchronization timeout in seconds
        """

        self.message = 'The subscriber did not synchronized with coordinator within {timeout} seconds'.format(
            timeout=timeout
        )

        super(CoveritySyncError, self).__init__(self.message)


class CoverityReportError(CoverityError):
    """Thrown when a timeout occurs in synchronization between subscriber and coordinator"""

    def __init__(self, message):
        """
        :param message: The error message retrieved from the caller
        """

        self.message = message

        super(CoverityReportError, self).__init__(self.message)


class DatabaseError(Exception):
    """Thrown if a database error is encountered"""

    def __init__(self, message):

        self.message = message

        super(DatabaseError, self).__init__(self.message)
