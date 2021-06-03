#!/usr/bin/python
"""
service.py:
This script contains the definition of a generic automation interface
Any specific automation should inherit from this class
"""

from __future__ import division  # enables floating point division

import inspect
import sys

__copyright__ = "Copyright 2021 NXP"


class AutomationJob(object):
    """Abstraction for a job. Effective job implementations must derive this class."""
    def pre_run(self):
        """The effective pre job execution logic."""
        raise NotImplementedError('Cannot call method {0} of abstract class {1} instance'
                                  .format(inspect.currentframe().f_code.co_name, self.__class__.__name__))

    def run(self):
        """The effective job execution logic."""
        raise NotImplementedError('Cannot call method {0} of abstract class {1} instance'
                                  .format(inspect.currentframe().f_code.co_name, self.__class__.__name__))

    def set_preconditions(self, preconditions):
        """Sets the attributes for this job.
        :param preconditions: The preconditions to be met for executing the job
        """
        self.preconditions = preconditions

    def set_configuration(self, configuration):
        """Sets the configuration for this job.
        :param configuration: The current configuration for this job
        """
        self.configuration = configuration

    def set_do_not_use_artifacts(self, do_not_use_artifacts):
        """Sets flag for artifacts."""
        self.do_not_use_artifacts = do_not_use_artifacts

    def set_use_nightly_artifacts(self, use_nightly_artifacts):
        """Sets flag for nightly artifacts."""
        self.use_nightly_artifacts = use_nightly_artifacts

    def set_is_last(self, is_last):
        """Sets flag for artifacts."""
        self.is_last = is_last

    def are_preconditions_met(self):
        """Checks to see if all preconditions are met.
        The effective implementation must be written in the derived class.
        """
        if not self.preconditions:
            return True

    @property
    def system_configuration_file(self):
        """Get the path to the system configuration file."""
        print(
            'No environment variables configuration file provided! Job will '
            'run with the default environment existing on automation system'
        )

    def __run_using_specific_system_configuration(self):
        """Set specific system configuration and run the job."""
        if not self.do_not_use_artifacts:
            self.pre_run()

        # Run a job (the environment variables will be loaded later)
        self.run()

    def do_run(self):
        """Runs the job."""
        if not self.are_preconditions_met():
            print 'The static [XML defined] preconditions for running the job are: {0}'.format(
                self.preconditions
            )
            print 'Not all preconditions for running job {0} are met. Aborting execution'.format(
                self.__class__.__name__
            )
            print >> sys.stderr, 'Further job execution is skipped.'
            return

        print 'All preconditions for running job {0} are met. Continuing with execution.'.format(
            self.__class__.__name__
        )
        self.__run_using_specific_system_configuration()
