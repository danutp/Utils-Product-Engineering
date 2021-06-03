#!/usr/bin/python
"""
concurrency.py: This module contains helper routines related to concurrency (multi-threading, multi-process)
"""

__copyright__ = "Copyright 2018-2020 NXP"

import hashlib
import inspect
import os
import sys
import traceback

from nxp.utilsNG.generic.exceptions import DatabaseError
from nxp.utilsNG.helper.constants import DatabaseConstants
from nxp.utilsNG.helper.sqlite_utils import SqliteUtils
from threading import Lock as ThreadLock, Thread
from time import time, sleep
from datetime import datetime


class Lock(object):
    """
    Lock abstract class
    """

    def acquire(self, timeout=1):
        """
        Try to acquire the exclusive lock for the specified timeout
        Must be implemented in derived classes
        :param timeout: timeout in seconds
        :return: True if successful, False otherwise
        """
        raise NotImplementedError('Cannot call method {0} of abstract class {1} instance'
                                  .format(inspect.currentframe().f_code.co_name, self.__class__.__name__))

    def release(self):
        """
        Release the lock
        Must be implemented in derived classes
        """
        raise NotImplementedError('Cannot call method {0} of abstract class {1} instance'
                                  .format(inspect.currentframe().f_code.co_name, self.__class__.__name__))

    def is_acquired(self):
        """
        Determines the conditions in which the lock was acquired.
        Must be implemented in derived classes
        :return:
        """
        raise NotImplementedError('Cannot call method {0} of abstract class {1} instance'
                                  .format(inspect.currentframe().f_code.co_name, self.__class__.__name__))


class FileLock(Lock):
    """
    Implements a lock via the exclusive access to a file
    """

    def __init__(self, path):
        """
        :param path: the path to the file used as a lock
        """
        # the import is done locally in order to avoid circular dependency (utils->concurrency->utils)
        from nxp.utilsNG.helper.utils import Utils
        self.unique_id = hashlib.md5(os.path.split(path)[1]).hexdigest()
        self.__lock_path = os.path.join(os.path.split(path)[0], self.unique_id)
        self.__lock_reference = path
        self.__is_acquired = False
        max_path = Utils.get_max_path()
        if len(self.__lock_path) > max_path:
            raise Exception('The requested lock path is longer than max path allowed {0}: {1} has {2} characters'.
                            format(max_path, self.__lock_path, len(self.__lock_path)))
        self.__lock_fd = None

    def acquire(self, timeout=1):
        """Overridden method of `Lock` class"""
        if timeout < 1:
            raise Exception('A file lock cannot be created with timeout less than 1 second')

        if self.is_acquired():
            raise Exception('Illegal usage: FileLock is not re-entrant')

        start_time = time()
        while True:
            try:
                self.__lock_fd = os.open(self.__lock_path, os.O_CREAT | os.O_WRONLY | os.O_EXCL)
            except OSError:
                sleep(0.1)  # give other threads the chance to execute, before retrying to acquire the lock
            else:
                os.write(self.__lock_fd, self.__lock_reference)
                os.fsync(self.__lock_fd)
                os.close(self.__lock_fd)
                self.__is_acquired = True
                return True  # lock successfully acquired
            if time() >= start_time + timeout:
                print 'Timeout [{} seconds] for acquiring a lock to {} expired'.format(timeout, self.__lock_reference)
                break
        return False

    def release(self):
        """Overridden method of `Lock` class"""
        try:
            retries = 100
            if self.__lock_fd is not None:
                while os.path.isfile(self.__lock_path) and (retries > 0):
                    try:
                        # give started threads a chance to be stopped
                        sleep(1)
                        os.remove(self.__lock_path)
                        retries -= 1
                    except OSError:
                        try:
                            os.close(self.__lock_fd)
                        except OSError:
                            pass

                if os.path.exists(self.__lock_path):
                    raise Exception('The file lock could not be released'.format(self.__lock_path))

        finally:
            self.__is_acquired = False
            self.__lock_fd = None

    def is_acquired(self):
        """Overridden method of `Lock` class"""
        return self.__is_acquired

    def get_lock_path(self):
        """Returns the path of the locked file"""
        return self.__lock_path


class Task(object):
    """
    Definition of a task which can be scheduled for executed by a dispatcher via a worker
    """

    def __init__(self, id_):
        """"
        :param: id_ The task id [string]
        """
        self.__id = id_

    @property
    def id(self):
        """"
        Getter for the `id` member
        """
        return self.__id

    def run(self):
        """"
        Execute task
        """
        raise NotImplementedError('Cannot call method {} of abstract class {} instance'
                                  .format(inspect.currentframe().f_code.co_name, self.__class__.__name__))

    class TaskState(object):
        """
        The states of a task
        """
        Not_Started, In_Execution, Finished, Failed = ["Not_Started", "In_Execution", "Finished", "Failed"]

        def __init__(self):
            pass

        @staticmethod
        def is_valid(state):
            return state in [Task.TaskState.Not_Started,
                             Task.TaskState.In_Execution,
                             Task.TaskState.Finished,
                             Task.TaskState.Failed]


class AbstractTaskDispatcher(object):
    """"
    Dispatcher used to schedule the parallel execution of a pool of tasks, over a distributed system
    [i.e. different processes running on different machines].
    It uses a `Lock` mechanism to handle concurrent access to the tasks.

    System description:

    - A pool of tasks which have to be executed in parallel on different machines.
    Each task is executed as a separate thread which is called a worker

    - A task is assigned to a worker by dispatchers.
    Each machine which is part of the distributed system must run must run a dispatcher

    - The dispatchers will synchronize over the existing tasks and their execution status
    [not started, in execution, finished] by using a database [e.g. file, memory]. The access to the tasks database is
    guarded by a lock mechanism

    - The first dispatcher will initialize the tasks database, by assigning each task the "Not Started" state

    - Each dispatcher will try to acquire the next task which is in "Not Started" state. Upon acquiring a task,
    the dispatcher changes the task state to "in Execution" and assigns it to a worker to execute it

    - If there is no more tasks to be executed the first dispatcher which will inquiry the tasks database
    will delete it
    """

    def __init__(self, tasks, agent_id, logging=False):
        """
        :param tasks: The list of tasks are to be managed by the dispatcher
        :param agent_id: The name of the remote agent which runs the tasks
        :param logging: Prints debug messages
        """
        self.run = True
        self.__tasks = tasks
        self.__agent_id = agent_id
        self.__logging = logging

    def init_tasks_database(self):
        """"
        Initializes the databases which keeps the tasks states
        """
        raise NotImplementedError('Cannot call method {} of abstract class {} instance'
                                  .format(inspect.currentframe().f_code.co_name, self.__class__.__name__))

    def delete_tasks_database(self):
        """"
        Deletes the databases which keeps the tasks states
        """
        raise NotImplementedError('Cannot call method {} of abstract class {} instance'
                                  .format(inspect.currentframe().f_code.co_name, self.__class__.__name__))

    def get_tasks_lock(self):
        """"
        :return: the lock used to guard concurrent access to the tasks database, hence to the execution of tasks
        """
        raise NotImplementedError('Cannot call method {} of abstract class {} instance'
                                  .format(inspect.currentframe().f_code.co_name, self.__class__.__name__))

    def task_finished_callback(self, task_id, result):
        """"
        This is a callback executed upon a task being finished.
        It must be implemented in the derived classes
        :param task_id: The id of the task which call back.
        :param result: Shows if the task passed or not.
        :return:
        """
        raise NotImplementedError('Cannot call method {} of abstract class {} instance'
                                  .format(inspect.currentframe().f_code.co_name, self.__class__.__name__))

    def acquire_task(self):
        """"
        Acquires a new task to be executed
        :return:
        - The acquired task or None if no task available
        - `True` is there are some tasks which are still in execution. `False` otherwise
        """
        raise NotImplementedError('Cannot call method {} of abstract class {} instance'
                                  .format(inspect.currentframe().f_code.co_name, self.__class__.__name__))

    def get_agents(self):
        """
        This function gets the remote agents from the agents database file.
        :return a list with remote agents names
        """
        raise NotImplementedError('Cannot call method {} of abstract class {} instance'
                                  .format(inspect.currentframe().f_code.co_name, self.__class__.__name__))

    def register_agent(self):
        """
        Registers an agent that it's running tasks. The registration is done by writing
        the agent id in a registration database.
        """
        raise NotImplementedError('Cannot call method {} of abstract class {} instance'
                                  .format(inspect.currentframe().f_code.co_name, self.__class__.__name__))

    def unregister_agent(self):
        """
        Marks the agent as free [i.e. not executing any tasks] by un-registering it from the agents database.
        """
        raise NotImplementedError('Cannot call method {} of abstract class {} instance'
                                  .format(inspect.currentframe().f_code.co_name, self.__class__.__name__))

    @property
    def tasks(self):
        """
        :return: The tasks to be executed
        """
        return self.__tasks

    @property
    def agent_id(self):
        """
        :return: The agent id
        """
        return self.__agent_id

    def __safe_init_tasks_database(self):
        """"
        Tries to acquire a lock to the tasks database,
        then initializes all tasks with 'Task.TaskState.Not_Started' state
        """
        lock = None
        try:
            lock = self.get_tasks_lock()
            if lock.acquire():
                self.log('Initializing the tasks database')
                self.init_tasks_database()
        finally:
            if lock and lock.is_acquired():
                lock.release()

    def __safe_delete_tasks_database(self):
        """
        Tries to acquire a lock to the tasks database, then deletes it
        :return: tasks database has been deleted
        """
        # all tasks have finished executing, try to delete the tasks database
        lock = None

        # noinspection PyBroadException
        try:
            lock = self.get_tasks_lock()
            if lock.acquire():
                self.log('Deleting the tasks database')
                self.delete_tasks_database()
                return True
        except Exception:
            return False
        finally:
            if lock and lock.is_acquired():
                lock.release()

    def __safe_acquire_task(self):
        """
        Determines the next task to be executed.
        A task is locked for execution by modifying its state in the tasks database
        :return:
        - A lock could be acquired
        - The acquired task or None if no task was acquired
        - There are some tasks which are still in execution
        """
        self.log('Trying to acquire a task for execution')
        lock = None

        try:
            lock = self.get_tasks_lock()
            if lock.acquire():
                self.log('A lock to the tasks database has been acquired. Searching for tasks.')
                t_id, tasks_remaining = self.acquire_task()
                return True, t_id, tasks_remaining
            else:
                self.log('A lock to tasks database could not be acquired')
                return False, None, False
        except Exception as e:
            print e
            traceback.print_exc()
        finally:
            if lock and lock.is_acquired():
                print 'Attempting to release the lock to the tasks database.'
                lock.release()
                print 'The lock to the tasks database has been released.'

    def log(self, message):
        """"
        Prints a message
        :param: message Text to be logged
        """
        if self.__logging:
            print '[{}] Dispatcher: {}'. format(
                datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f'), message)

    def get_task_by_id(self, id_):
        """"
        :return: the task corresponding to a given id
        """
        for t in self.__tasks:
            if t.id == id_:
                return t

        raise Exception('Dispatcher: No task with id {} is known by the dispatcher'.format(id_))

    def dispatch(self, multi_threaded=False):
        """"
        Tries to execute the next available task by assigning it to a worker.
        If all task have executed, tries to delete the tasks database

        :params: multi_threaded Allows multi-threaded execution of workers
        (i.e. multiple workers will be executed concurrently in separate threads)
        """

        # dispatch task execution to a worker as long a there are tasks to be executed
        self.__safe_init_tasks_database()
        while self.run:
            acquired, task, executing = self.__safe_acquire_task()
            if not acquired:
                self.log('Task could not be acquired. Retrying...')
                continue  # keep trying to acquire a lock to the tasks database

            if not task:
                # no tasks remain to be executed
                self.log('No tasks remaining to be executed. Unregistering agent {}'.format(self.agent_id))
                break

            self.log('Task {} acquired for execution'.format(task.id))
            # execute the acquired task using a worker
            worker = Worker(task, self.task_finished_callback)
            worker.start()
            if not multi_threaded:
                worker.join()  # Blocks the caller until the worker finishes (i.e. one worker at a time)

        # Un-registers the agent from the list after his work is done
        self.unregister_agent()


class Worker(Thread):
    """"
    Generic worker who can execute any given task. The worker will executed in a separate thread by the caller.
    """

    def __init__(self, task, termination_callback):
        """
        :param task: the task to be executed represented by a `Task` instance
        :param termination_callback: the callback function used to notify that the task has been executed
        """
        self.__task = task
        self.__termination_callback = termination_callback
        self.__exception = None  # stores the exception info this thread run execution may have resulted in
        super(Worker, self).__init__()

    def run(self):
        """
        Worker thread main routine
        """
        self.__exception = None
        # noinspection PyBroadException
        try:
            self.log('Task {} execution has started'.format(self.__task.id))
            result = self.__task.run()
            self.__termination_callback(self.__task.id, result)
            self.log('Task {} execution has ended'.format(self.__task.id))

            # raise the exception to the caller in case the task failed
            if result == Task.TaskState.Failed:
                raise Exception('Task {} failed'.format(self.__task.id))
        except Exception:
            self.__exception = sys.exc_info()

    def join(self, timeout=None):
        super(Worker, self).join(timeout=timeout)

        # make the exception occurred during run visible to the joined thread
        if self.__exception:
            message = 'Thread {} threw an exception: {}'.format(self.getName(), self.__exception[1])
            new_exc = Exception(message)
            raise new_exc.__class__, new_exc, self.__exception[2]

    def log(self, message):
        print '[{}] Worker for task {}: {}'.format(time(), self.__task.id, message)


class FileBasedTaskDispatcher(AbstractTaskDispatcher):
    """
    A task dispatcher which uses:
    - a file to implement the tasks database
    - a FileLock to handle concurrent access to the tasks database
    """

    def __init__(self, tasks_state_file, tasks, agent_id, agents_database, logging=False):
        """"
        :param tasks_state_file: The file where the tasks'states are kept.
        Line X from this file contains the following info <task_X_id>#<task_X_state>,
        where X is the 0-based id of the task
        :param tasks: The list of tasks to be managed by the dispatcher
        :param agent_id: The name of the remote agent which runs the tasks
        :param agents_database: The database where the agents names are kept, each line contains
        :param logging: Prints debug messages
        the name of the remote agent that runs the same tasks as the other ones.
        """
        super(FileBasedTaskDispatcher, self).__init__(tasks=tasks, agent_id=agent_id, logging=logging)
        self.__tasks_state_file = tasks_state_file
        self.agents_database = agents_database
        self.register_agent()

    @property
    def tasks_state_file(self):
        """
        :return: The file used to store the tasks states
        """
        return self.__tasks_state_file

    @property
    def lock_file(self):
        """"
        :returns: The lock file used to synchronize the access to the tasks states file
        """
        return self.tasks_state_file + '_lock'

    def init_tasks_database(self):
        """
        Initializes all tasks states to `Task.TaskState.Not_Started` via writing in the tasks states file
        """
        if os.path.isfile(self.tasks_state_file):
            self.log('Tasks database already initialized.')
            return

        with open(self.tasks_state_file, 'w') as f:
            for task in self.tasks:
                f.write(str(task.id) + '#' + Task.TaskState.Not_Started + '\n')
            # wait for the write to finish
            from nxp.utilsNG.helper.utils import Utils
            Utils.wait_for_disk_write(f)

    def delete_tasks_database(self):
        """
        Deletes the tasks states file
        """
        if os.path.isfile(self.tasks_state_file):
            self.log('Deleting tasks database')
            os.remove(self.tasks_state_file)

    def get_tasks_lock(self):
        """
        :return: A file based lock, used to guard access to the tasks file
        """
        return FileLock(self.lock_file)

    def acquire_task(self):
        """"
        Acquires a new task to be executed
        :return:
        - The acquired task or None if no task available
        - `True` is there are some tasks which are still in execution. `False` otherwise
        """
        if not os.path.isfile(self.tasks_state_file):
            self.log('Tasks database does not exist!')
            return None, False

        with open(self.tasks_state_file, 'r') as f:
            lines = f.readlines()

        tasks = dict()
        for line in lines:
            line = line.rstrip(os.linesep)
            t_id, t_state = line.split('#')
            tasks[t_id] = t_state

        for t_id, t_state in tasks.iteritems():
            if t_state == Task.TaskState.Not_Started:
                self.log('Task {} selected for execution. Changing its status to "In Execution"'.format(t_id))
                self.__switch_task_state(t_id,
                                         Task.TaskState.Not_Started,
                                         Task.TaskState.In_Execution)
                return self.get_task_by_id(t_id), True

        return None, False

    def __switch_task_state(self, task_id, current_state, new_state):
        """"
        Moves a task from one state to the other by writing the new state in the tasks file
        :param: task_id Task to be transitioned between states
        :param: current_state Current state of the task
        :param: new_state New state of the task
        """

        # the import is done locally in order to avoid circular dependency (utils->concurrency->utils)
        from nxp.utilsNG.helper.utils import Utils

        # The tasks state file is located on a mapped network drive and its state may not be updated in real time
        # so we must wait (up to a timeout) until the file is released.
        Utils.wait_for_file_write_access(self.tasks_state_file, 20)

        Utils.replace_tokens_in_text_file(self.tasks_state_file,
                                          ['^' + str(task_id) + '#' + current_state],
                                          [str(task_id) + '#' + new_state])

    def task_finished_callback(self, task_id, result):
        """"
        This function is called by the worker and it notifies the dispatcher the task is finished.
        :param task_id: The id of the task executed by the worker which called back finishing its execution
        :param result: Task execution result: finished successfully or failed
        """
        self.log('Attempting to finalize task {} which ended with status: {}'.format(task_id, result))
        # acquire a lock on task_state file in order to write the new state of the task
        lock = None

        # noinspection PyBroadException
        try:
            lock = self.get_tasks_lock()
            agents_left = len(self.get_agents())

            # default timeout of 1 second seems not to be enough in some cases,
            # so we set it adaptive based on the agents which might try to acquire the same lock
            # if all tasks were finished, then this is the last remaining agent
            if lock.acquire(timeout=100 * (agents_left + 1)):
                self.log('Task {0} finished with status: {1}.'.format(task_id, result))
                if result == Task.TaskState.Failed:
                    if agents_left > 1:
                        # If the task fails on a remote agent, stop it and let other agents execute it
                        # For that, at least one additional agent (beyond the current one) needs to exist,
                        # so a minimum of 2
                        self.__switch_task_state(task_id, Task.TaskState.In_Execution, Task.TaskState.Not_Started)
                        self.run = False
                        self.log('Task {} was reset, so that other agent will execute it.')
                    else:
                        # There are no more agents left, beyond this one
                        self.__switch_task_state(task_id, Task.TaskState.In_Execution, result)
                        raise Exception('There are no more agents left to re-execute task {}.'.format(task_id))
                else:
                    self.__switch_task_state(task_id, Task.TaskState.In_Execution, result)
                return True
            else:
                raise Exception('A lock could not be acquired in order to set task {} as finished'.format(task_id))
        finally:
            if lock and lock.is_acquired():
                lock.release()

    def get_agents(self):
        """
        Get the list of remote agents which a task can be assigned to.
        :return a list with remote agents names
        """
        with open(self.agents_database, mode='r') as f:
            agents = f.readlines()

        return [a.strip('\n') for a in agents]

    def register_agent(self):
        """
        Registers an agent that it's running tasks. The registration is done by writing
        the agent id in a registration database.
        """
        # acquire a lock on agents database to register an agent
        lock = None
        # noinspection PyBroadException
        try:
            lock = FileLock(self.agents_database + '_lock')
            if lock.acquire():
                with open(self.agents_database, 'a+') as f:
                    f.write(self.agent_id + '\n')
                    # wait for the write to finish
                    from nxp.utilsNG.helper.utils import Utils
                    Utils.wait_for_disk_write(f)
                self.log('Remote agent {0} has been registered.'.format(self.agent_id))
        except Exception:
            raise Exception('Could not acquire a lock to register agent {0}'.format(self.agent_id))
        finally:
            if lock and lock.is_acquired():
                lock.release()

    def unregister_agent(self):
        """
        Marks the agent as free [i.e. not executing any tasks] by un-registering it from the agents database.
        """
        # acquire a lock on agents database to un-register an agent
        lock = None
        # noinspection PyBroadException
        try:
            lock = FileLock(self.agents_database + '_lock')
            if lock.acquire():
                with open(self.agents_database, 'r+') as f:
                    agents = f.readlines()
                    f.seek(0)
                    for agent in agents:
                        if self.agent_id != agent.strip('\n'):
                            f.write(agent)
                    f.truncate()
                    # wait for the write to finish
                    from nxp.utilsNG.helper.utils import Utils
                    Utils.wait_for_disk_write(f)
                self.log('Remote agent {0} has been un-registered.'.format(self.agent_id))
        except Exception:
            raise Exception('Could not acquire a lock to un-register agent {0}'.format(self.agent_id))
        finally:
            if lock and lock.is_acquired():
                lock.release()


class ThreadingLock(Lock):
    """Simple wrapper over threading Lock."""

    def __init__(self):
        self.lock = ThreadLock()

    def acquire(self, timeout=1):
        """Used to acquire a lock wihtin a "timeout" seconds interval.
        :param timeout: The timeout for acquiring a lock
        :return: None
        """
        while timeout:
            if self.lock.acquire(False):
                return True
            print('Waiting {0} seconds for other threads to finish their job'.format(timeout))
            if timeout == 1:
                print('Timeout for acquiring lock has expired ({0} seconds)'.format(timeout))
                return False
            timeout -= 1
            sleep(1)

    def release(self):
        """Release a lock.
        :return: None
        """
        self.lock.release()

    def is_acquired(self):
        """Return the lock status.
        :return bool, True if lock is acquired, False otherwise
        """
        return self.lock.locked()


class DatabaseLock(object):
    """Database locking mechanism for shared resources"""

    def __init__(self, database_file, table_name, resource_id):

        self.__database_file = database_file
        self.__table_name = table_name
        self.__resource_id = resource_id
        self.__is_acquired = False
        self.__sqlite_connection = SqliteUtils(sqlite_file=database_file, table_name=table_name)
        self.__sql_constants = DatabaseConstants()

    @property
    def sqlite_connection(self):
        """Getter for SQL connection"""

        return self.__sqlite_connection

    @property
    def sql_constants(self):
        """Getter for SQL constants"""

        return self.__sql_constants

    @sql_constants.setter
    def sql_constants(self, sql_constants_value):
        """Setter for SQL constants"""

        self.__sql_constants = sql_constants_value

    def set_lock_status(self, lock_status=True, timeout=None):
        """Set lock status for a resource
        :param lock_status: 1 - locked, 0 - unlocked
        :param timeout: Optional argument used when locking a resource
        """

        sql_command = (
            self.sql_constants.COMMANDS.UPDATE.format(
                table_name=self.__table_name,
                lock_status=lock_status,
                resource_id=self.__resource_id,
                **self.sql_constants.TABLE_FIELDS
            )
        )
        query_response = False
        if lock_status:
            if timeout:
                start_time = time()
                while time() < start_time + timeout:
                    if not self.__get_lock_status():
                        query_response = self.__sqlite_connection.run_query_db(sql_command)
                        break
                    else:
                        print('Resource locked, retrying in {0} seconds'.format(self.sql_constants.LOCK_WAIT_TIME))
                    sleep(self.sql_constants.LOCK_WAIT_TIME)
            else:
                if not self.__get_lock_status():
                    query_response = self.__sqlite_connection.run_query_db(sql_command)

            message = (
                'Successfully set a lock for resource "{resource_id}"' if query_response else
                'Failed to lock the resource "{resource_id}"'
            )
            print(message.format(resource_id=self.__resource_id))
            return query_response

        if timeout:
            print('Timeout parameter not valid for releasing a lock, ignoring...')

        query_response = self.__sqlite_connection.run_query_db(sql_command)
        message = (
            'Successfully released lock for resource "{resource_id}"' if query_response else
            'Failed to release the lock for resource "{resource_id}"'
        )
        print(message.format(resource_id=self.__resource_id))
        return query_response

    def __get_lock_status(self):
        """Get lock status"""

        sql_command = self.sql_constants.COMMANDS.IS_LOCKED.format(
            table_name=self.__table_name,
            resource_id=self.__resource_id,
            **self.sql_constants.TABLE_FIELDS
        )
        response = self.__sqlite_connection.fetch_query_db(sql_command)
        if not response:
            return False

        if len(response) > 1:
            raise DatabaseError('Multiple entries for "{resource_id_field}" found. Please check database'.format(
                **self.sql_constants.TABLE_FIELDS
            ))

        return response[0][0]
