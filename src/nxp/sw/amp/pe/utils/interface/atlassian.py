#!/usr/bin/python
"""
atlassian.py:
This script contains the interface over Atlassian Rest API: JIRA, Bitbucket, Bamboo.
"""


from __future__ import division  # enables floating point division
import base64
import inspect
import itertools
import json
import os
import re
import sqlite3
import time
import threading

from bs4 import BeautifulSoup
from collections import defaultdict, namedtuple
from distutils import util
from nxp.sw.amp.pe.utils.helper.pull_request import ReviewStatistics
from nxp.sw.amp.pe.utils.helper.rest import HttpStatusCodes, RESTUtils
from nxp.sw.amp.pe.utils.helper.utils import Utils
from multiprocessing.pool import ThreadPool
from multiprocessing import cpu_count
from random import randrange
from service import AutomationJob
from tldextract import extract


__copyright__ = "Copyright 2021 NXP"


class BitbucketTag(object):
    """
    POD class for storing the attributes of a tag in Bitbucket
    """

    def __init__(self, name, latest_commit):
        self.name = name
        self.latest_commit = latest_commit


class AtlassianAccount(object):
    """
    Class that stores credentials for using AtlassianUtils services
    """

    def __init__(self):
        self.__username = None
        self.__password = None

    @property
    def username(self):
        """Get the username"""
        return self.__username

    @username.setter
    def username(self, username_value):
        """Set the username"""

    @property
    def password(self):
        """Get the decoded password"""

        return base64.b64decode(self.__password)

    @password.setter
    def password(self, password_value):
        """Set the encoded password"""

        self.__password = password_value


class AtlassianUtils(object):
    """
    Helper class used for operation with Atlassian suite [JIRA, BAMBOO, Bitbucket] via REST API
    """

    # CONSTANTS

    # JIRA constants:

    # JIRA link
    JIRA_URL = 'https://jira.sw.nxp.com/'

    # JIRA authentication URL
    JIRA_AUTH_URL = JIRA_URL + 'rest/auth/latest/session'

    # Information about a Jira issue
    JIRA_DEFECT_INFO_URL = JIRA_URL + 'rest/api/latest/issue/{0}'

    # Information about the editable fields of a JIRA defect
    JIRA_DEFECT_EDIT_INFO_URL = JIRA_URL + 'rest/api/latest/issue/{0}/editmeta'

    # Information about possible status transitions for Jira issues
    JIRA_DEFECT_TRANSITIONS_INFO_URL = JIRA_URL + 'rest/api/latest/issue/{0}/transitions'

    # Information about possible status transitions for Jira issues with the required transition fields expanded
    JIRA_DEFECT_TRANSITIONS_INFO_EXTENDED_URL = (
        JIRA_URL + 'rest/api/latest/issue/{0}/transitions?expand=transitions.fields'
    )

    # Run a query in JIRA using JQL
    JIRA_QUERY_URL = JIRA_URL + 'rest/api/latest/search'

    # Search for JIRA users which are assignable to a project
    JIRA_USER_SEARCH_URL = JIRA_URL + 'rest/api/latest/user/assignable/search?project={0}{1}'

    # BITBUCKET constants:

    # Bitbucket link
    BITBUCKET_URL = 'https://bitbucket.sw.nxp.com/'

    # Creates a tag in the specified repository
    BITBUCKET_SET_TAG_URL = BITBUCKET_URL + 'rest/api/latest/projects/{0}/repos/{1}/tags'

    # Get all tags from the specified repository
    BITBUCKET_GET_TAGS_URL = BITBUCKET_URL + 'rest/api/latest/projects/{0}/repos/{1}/tags?start={2}&limit=1000'

    # Get all branches from the specified repository
    BITBUCKET_GET_BRANCHES_URL = (
        BITBUCKET_URL + 'rest/api/latest/projects/{0}/repos/{1}/branches'
    )

    # Get all branches from the specified repository - paged
    BITBUCKET_GET_BRANCHES_PAGED_URL = (
        BITBUCKET_GET_BRANCHES_URL + '?start={2}&limit=1000'
    )

    # Get branch details
    BITBUCKET_GET_BRANCH_DETAILS_URL = (
        BITBUCKET_GET_BRANCHES_URL + '?details=true&filterText={2}'
    )

    # Get all changes from the specified repository and branch
    BITBUCKET_GET_CHANGES_URL = (
            BITBUCKET_URL + 'rest/api/latest/projects/{0}/repos/{1}/compare/changes?from={2}&start={3}&limit=1000'
    )

    # Get all commits from the specified repository
    BITBUCKET_GET_COMMITS_URL = BITBUCKET_URL + 'rest/api/latest/projects/{0}/repos/{1}/commits?start={2}&limit=1000'

    # Get all commits between two commits
    BITBUCKET_GET_COMMITS_RANGE_URL = (
            BITBUCKET_URL + 'rest/api/latest/projects/{0}/repos/{1}/commits?since={2}&until={3}&start={4}&limit=1000'
    )

    # Queries pull requests for a branch
    BITBUCKET_GET_PULL_REQUESTS_URL = (
        BITBUCKET_URL +
        'rest/api/latest/projects/{0}/repos/{1}/pull-requests?at=refs/heads/{2}&direction={3}&state={4}'
        '&start={5}&limit=1000'
    )

    # Queries all pull requests
    BITBUCKET_GET_ALL_PULL_REQUESTS_URL = (
        BITBUCKET_URL +
        'rest/api/latest/projects/{0}/repos/{1}/pull-requests?direction={2}&state={3}&start={4}&limit=1000'
    )

    # Get a pull request's activities
    BITBUCKET_GET_PULL_REQUEST_ACTIVITY_URL = (
        BITBUCKET_URL +
        'rest/api/latest/projects/{0}/repos/{1}/pull-requests/{2}/activities?start={3}&limit=1000'
    )

    # Pull request merge/get merge info
    BITBUCKET_PULL_REQUEST_MERGE_URL = (
        BITBUCKET_URL +
        'rest/api/latest/projects/{0}/repos/{1}/pull-requests/{2}/merge'
    )

    # Pull request get/set info
    BITBUCKET_PULL_REQUEST_INFO_URL = BITBUCKET_URL + 'rest/api/latest/projects/{0}/repos/{1}/pull-requests/{2}'

    # Pull request get changes
    BITBUCKET_GET_PULL_REQUEST_CHANGES_URL = (
            BITBUCKET_URL + 'rest/api/latest/projects/{0}/repos/{1}/pull-requests/{2}/changes'
    )

    # Pull request get paged changes
    BITBUCKET_PULL_REQUEST_PAGED_CHANGES_URL = BITBUCKET_GET_PULL_REQUEST_CHANGES_URL + '?start={3}&limit=1000'

    # Get all files from a specified repository
    BITBUCKET_GET_FILES_URL = BITBUCKET_URL + 'rest/api/1.0/projects/{0}/repos/{1}/browse?start={2}&limit=1000'

    # Get a file from a specified repository
    BITBUCKET_GET_FILE_URL = BITBUCKET_URL + 'rest/api/1.0/projects/{0}/repos/{1}/browse/{2}'

    # BAMBOO constants:

    # Bamboo plan link
    BAMBOO_URL = 'https://{0}.sw.nxp.com/'

    # Bamboo queue post build to queue
    BAMBOO_QUEUE_POST_REQUEST_URL = BAMBOO_URL + 'rest/api/latest/queue/{1}'

    # Bamboo request specifying the branch for plan
    BAMBOO_PLAN_BRANCH_REQUEST_URL = BAMBOO_URL + 'rest/api/latest/plan/{1}/branch/{2}.json'

    # Bamboo request for getting plan branches
    BAMBOO_GET_PLAN_BRANCHES_INFO_URL = BAMBOO_URL + 'rest/api/latest/plan/{1}/branch.json?max-result=1000'

    # Bamboo request for triggering plan
    BAMBOO_TRIGGER_PLAN_URL = BAMBOO_URL + 'rest/api/latest/queue/'

    # Bamboo request for stopping plan
    BAMBOO_STOP_PLAN_URL = BAMBOO_URL + 'build/admin/stopPlan.action'

    # Bamboo request for getting plan results
    BAMBOO_PLAN_RESULTS_URL = BAMBOO_URL + 'rest/api/latest/result/'

    # Bamboo request for querying plan
    BAMBOO_QUERY_PLAN_URL = BAMBOO_URL + 'rest/api/latest/plan/'

    # Bamboo request for querying plan queue
    BAMBOO_LATEST_QUEUE_URL = BAMBOO_URL + 'rest/api/latest/queue.json'

    # Bamboo request for getting artifact
    BAMBOO_ARTIFACT_URL = BAMBOO_URL + 'browse/{1}/artifact/{2}/{3}/'

    # Bamboo request for retrieving unfinished builds
    BAMBOO_GET_UNFINISHED_BUILDS = BAMBOO_URL + 'rest/api/{1}/result/{2}{3}?includeAllStates=true&buildstate=Unknown'

    # Bamboo request for retrieving Bamboo variables
    BAMBOO_GET_BUILD_BAMBOO_VARS_INFO = (
            BAMBOO_URL + 'rest/api/{1}/result/{2}-{3}{4}?includeAllStates=true&expand=variables'
    )

    def __init__(self,
                 username,
                 password):

        """
        :param username: The username to use for any Atlassian, REST call based operations
               By default it's a service account
        :param password: The (encoded) password to be used
        """

        self.__account_info = None
        self.__set_credentials(username, password)

    @property
    def account_info(self):
        """Get the account info"""

        return self.__account_info

    #
    # Each Bamboo variable is visible as an environment variable.
    # The environment variable name is obtained from the Bamboo variable name prefixed with this string: "bamboo_"
    #

    @staticmethod
    def get_env_var(key, env_variable_prefix='bamboo_', default_value=None):
        """
        Gets the value of a environment variable.
        :param key: Name of the environment variable
        :param env_variable_prefix: The prefix of the environment variables
        :param default_value:  Returned in case environment variable doesn't exist. Default is None.
        :return: The value of the environment variable
        """

        environment_variable_value = Utils.get_env(
            '{0}{1}'.format(env_variable_prefix, key), default_value=default_value)
        return environment_variable_value.strip() if environment_variable_value else environment_variable_value

    @staticmethod
    def get_bamboo_env(key, default_value=None):
        """
        Gets the value of a Bamboo variable.
        :param key: Name of the Bamboo variable
        :param default_value: Returned in case environment variable doesn't exist. Default is None.
        :return: The value of the Bamboo variable
        """
        return AtlassianUtils.get_env_var(key, default_value=default_value)

    @staticmethod
    def get_boolean_bamboo_env(key, default_value=False, env_variable_prefix='bamboo_'):
        """
        Gets the boolean value of a environment variable
        :param key: Name of the environment variable
        :param default_value: the default value of the variable if it isn't defined
        :param env_variable_prefix: the current build system
        """

        value = AtlassianUtils.get_env_var(key, env_variable_prefix)
        return util.strtobool(value) if value is not None else default_value

    @staticmethod
    def get_list_from_bamboo_env_var(key, delimiter=',', exclude_duplicates=True):
        """Gets the list of values of a Bamboo variable.
        :param key: Name of the Bamboo variable
        :param delimiter: Character used to separate values
        :param exclude_duplicates: flag that indicates if duplicates will be removed from the final list of values
        :return List of values
        """

        bamboo_variable_value = AtlassianUtils.get_bamboo_env(key)
        if not bamboo_variable_value:
            return []

        if delimiter != ' ':
            values = bamboo_variable_value.replace(' ', '').split(delimiter)
        else:
            values = bamboo_variable_value.split(delimiter)

        if exclude_duplicates:
            if len(values) != len(set(values)):
                print('Bamboo variable "{0}" contains duplicates'.format(key))

            return list(set(values))

        return values

    @staticmethod
    def get_child_element_by_key(storage, key, value):
        """
        Seeks in a dictionary given key's element [expected to be a list or dictionary] and retrieves the item
        matching a given value.
        :param storage: Storage to seek in
        :param key: Matching key
        :param value: Matching value
        :return:
        """

        for item in storage:
            if value in item[key]:
                if 'children' in item:
                    item['child'] = item['children'][0]
                    del item['children']

                return [item]
        return None

    @RESTUtils.pack_response_to_client
    def rest_get(self, url, headers=None, timeout=None, destination_file=None):
        """
        Runs a GET REST call on JIRA, Bitbucket or Bamboo
        :param url: REST service URL
        :param headers: The headers to be included in query
        :param timeout: The timeout to be used when waiting for response
        :param destination_file: File where artifact will be downloaded in case of such a request
        :return: REST call response object
        """

        if destination_file:
            return RESTUtils.download(url, auth=self.account_info, timeout=timeout, destination=destination_file)

        return RESTUtils.get(url,
                             headers=headers,
                             auth=self.account_info,
                             timeout=timeout)

    @RESTUtils.pack_response_to_client
    def rest_post(self, url, headers=None, payload=None, timeout=None):
        """
        Runs a POST REST call on JIRA
        :param url: REST service URL
        :param headers: The headers to be included in query
        :param payload: Payload used by the call
        :param timeout: The timeout to be used when waiting for response
        :return: REST call response object
        """

        return RESTUtils.post(url,
                              headers=headers,
                              auth=self.account_info,
                              payload=payload,
                              timeout=timeout)

    @RESTUtils.pack_response_to_client
    def rest_put(self, url, headers=None, payload=None, timeout=None):
        """
        Runs a PUT REST call on JIRA
        :param url: REST service URL
        :param headers: The headers to be included in query
        :param payload: Payload used by the call
        :param timeout: The timeout to be used when waiting for response
        :return: REST call response object
        """

        return RESTUtils.put(url,
                             headers=headers,
                             auth=self.account_info,
                             payload=payload,
                             timeout=timeout)

    @RESTUtils.pack_response_to_client
    def rest_delete(self, url, headers=None, payload=None, timeout=None):
        """
        Runs a POST REST call on JIRA
        :param url: REST service URL
        :param headers: The headers to be included in query
        :param payload: Payload used by the call
        :param timeout: The timeout to be used when waiting for response
        :return: REST call response object
        """

        return RESTUtils.delete(url,
                                headers=headers,
                                auth=self.account_info,
                                payload=payload,
                                timeout=timeout)

    def __set_credentials(self, username, password):
        """Set the credentials for the Atlassian account"""

        self.__account_info = AtlassianAccount()
        self.__account_info.username = username
        self.__account_info.password = password


class JiraUtils(AtlassianUtils):

    def __init__(self, jira_project_key, username, password):
        """
        :param jira_project_key: the unique project key (e.g. Jira)
        :param username: The username to use for any Atlassian, REST call based operations
        :param password: The (encoded) password to be used
        """

        super(JiraUtils, self).__init__(username, password)
        self.__jira_project_key = jira_project_key

    def project_key(self):
        """Get the Jira project key"""

        return self.__jira_project_key

    @staticmethod
    def jira_get_jira_ids(jql_result):
        """
        Return the JIRA IDs from a JQL execution result
        :param jql_result: the JQL execution result
        :return:
        """

        result = []
        for item in jql_result:
            result.append(item['key'])

        return result

    @staticmethod
    def jira_generate_defect_fields_custom_values(fields_values_dict):
        """
        Formats a given value in JSON format to be used for a JIRA defect field modification.
        :param fields_values_dict: dictionary containing <field, value> tuples
        :return: The formatted payload to be used in the field modification using REST API
        """

        payload = dict()
        payload['fields'] = {}
        for key, value in fields_values_dict.items():
            payload['fields'][key] = value
        return payload

    @staticmethod
    def jira_generate_defect_field_custom_value(field, value):
        """
        Formats a given value in JSON format to be used for a JIRA defect field modification.
        :param field: field to be modified
        :param value: field value
        :return: The formatted payload to be used in the field modification using REST API
        """

        return JiraUtils.jira_generate_defect_fields_custom_values(dict([(field, value)]))

    def jira_generate_defect_field_allowed_value(self, jira_id, field, value):
        """
        Generates an allowed value structure to be used for a JIRA defect field modification
        :param jira_id: JIRA ID
        :param field: field to be modified
        :param value: field value
        :return: The payload to be used with a REST API call in order to set the JIRA defect field value
        """

        url = AtlassianUtils.JIRA_DEFECT_EDIT_INFO_URL.format(jira_id)
        response = self.rest_get(url)
        if response.status_code != HttpStatusCodes.SUCCESS_OK:
            raise RuntimeError(
                'Cannot get defect information for jira id "{0}": {1}'.format(
                    jira_id, response.content)
            )
        data = json.loads(response.content)

        payload = dict()
        payload['fields'] = {}
        payload['fields'][field] = AtlassianUtils.get_child_element_by_key(data['fields'][field]['allowedValues'],
                                                                           'value', value)
        return payload

    def jira_set_defect_field(self, jira_id, field, value, custom=True):
        """
        Sets a new value for a JIRA defect field. The value is checked to be valid against the allowed values
        :param jira_id: JIRA ID
        :param field: Field to be updated
        :param value: New field value
        :param custom: The value to be set is custom [by default] or from a list of allowed values
        [as defined in the issue fields metadata]
        :return: The response code of the REST API request
        """

        if custom:
            payload = JiraUtils.jira_generate_defect_field_custom_value(field, value)
        else:
            payload = self.jira_generate_defect_field_allowed_value(jira_id, field, value)

        url = AtlassianUtils.JIRA_DEFECT_INFO_URL.format(jira_id)
        response = self.rest_put(url, payload=payload)
        return response.status_code

    def jira_get_transition_id(self, jira_id, to_status):
        """
        Gets the transition ID of a JIRA defect based on its transition metadata description
        :param jira_id: JIRA ID
        :param to_status: Status to which to transition to
        :return: The transition ID used to transition to the given status, or None if no such transition is defined
        """

        url = AtlassianUtils.JIRA_DEFECT_TRANSITIONS_INFO_EXTENDED_URL.format(jira_id)
        response = self.rest_get(url)
        if response.status_code != HttpStatusCodes.SUCCESS_OK:
            raise RuntimeError(
                'Cannot get jira transition id for "{0}" id: {1}'.format(
                    jira_id, response.content)
            )
        data = json.loads(response.content)

        for transition in data['transitions']:
            if transition['to']['name'] == to_status:
                return transition['id']

        print(
            'No transition to status {0} is defined in the JIRA ID {1} transitions metadata'.format(to_status, jira_id)
        )
        return None

    def jira_transition_defect(self, jira_id, to_status, change_set):
        """
        Transitions a JIRA defect from current status to a new given one.
        It assumes that all fields required for the transition to happen [as per transition metadata] have been set
        :param jira_id: JIRA ID to transition
        :param to_status: Status to transition to
        :param change_set: A JIRA transition requires that at least one fields is changes or updated.
        This is the payload to use for the update operation
        :return: REST call error code or None if the transition is not allowed
        """

        payload = dict()
        payload['transition'] = {}
        transition_id = self.jira_get_transition_id(jira_id, to_status)
        if transition_id is None:
            return None  # JIRA ID cannot be transitioned to requested state, because JIRA schema does not allow it

        payload['transition']['id'] = transition_id

        payload = dict(itertools.chain(payload.iteritems(), change_set.iteritems()))  # merge the 2 dictionaries

        url = AtlassianUtils.JIRA_DEFECT_TRANSITIONS_INFO_URL.format(jira_id)
        response = self.rest_post(url, payload=payload)
        return response.status_code

    def jira_get_defect_status(self, jira_id):
        """
        Gets a JIRA defect status
        :param jira_id: JIRA ID of whose status to seek for
        :return: The JIRA ID status
        """

        return self.jira_get_field_value_by_name(jira_id, 'status')

    def jira_get_field_value_by_name(self, jira_id, field_id):
        """
        Gets a JIRA fiels value by name
        :param jira_id: JIRA ID of whose status to seek for
        :param field_id: Field to retrieve the value of
        :return: name key from the value (dict) of the field
        """

        return self.jira_get_field_value(jira_id, field_id)['name']

    def jira_get_field_value(self, jira_id, field_id):
        """
        Gets a JIRA field value as Python object. The caller should know the structure of the returned object
        :param jira_id: JIRA ID
        :param field_id: Field to retrieve the value of
        """

        url = AtlassianUtils.JIRA_DEFECT_INFO_URL.format(jira_id)
        response = self.rest_get(url)
        if response.status_code != HttpStatusCodes.SUCCESS_OK:
            raise RuntimeError(
                'Cannot get jira field value for "{0}" id: {1}'.format(
                    jira_id, response.content)
            )
        data = json.loads(response.content)

        return data['fields'][field_id]

    def jira_get_jira_users(self, filters=None):
        """
        Retrieves the users of the JIRA project based on a filters dictionary [can be optional]
        :param filters: The filters dictionary [pairs of tuples]
        :return: The users, in a dictionary format
        """

        query = ''
        if filters is not None:
            for key in filters.keys():
                query += '&{0}={1}'.format(key, filters[key])

        url = AtlassianUtils.JIRA_USER_SEARCH_URL.format(self.project_key, query)
        response = self.rest_get(url)
        if response.status_code != HttpStatusCodes.SUCCESS_OK:
            raise RuntimeError(
                'Cannot get jira users for project "{0}": {1}'.format(
                    self.project_key, response.content)
            )
        return json.loads(response.content)

    def jira_is_user_assignable(self, user_id):
        """
        Determines if a given user id is assignable [can be used to fill in JIRA defect fields]
        in the context of the current project
        :param user_id: JIRA user id
        :return: True if the user is assignable, False otherwise
        """

        filters = dict([('username', user_id)])
        users = self.jira_get_jira_users(filters)
        count = len(users)
        if count > 1:
            raise Exception('Found multiple [{0}] definitions for the same user: {1}'.format(count, user_id))

        if count == 0:
            print('User {0} is not assignable for project {1}'.format(user_id, self.project_key))
            return False

        if users[0]['active'] == 'false':
            print('User {0} is not active'.format(user_id))
            return False

        return True

    def jira_run_query(self, query, max_results=None):
        """
        Runs a JIRA query and returns the results
        :param query: JQL query to run
        :param max_results: Maximum amount of results to be returned, if None all results will be returned
        :return: The JSON result of the JQL query
        """

        payload = {'jql': query}
        if max_results:
            payload['maxResults'] = '{0}'.format(max_results)

        response = self.rest_post(AtlassianUtils.JIRA_QUERY_URL, payload=payload)
        if response.status_code != HttpStatusCodes.SUCCESS_OK:
            raise RuntimeError(
                'Cannot run query "{0}": {1}'.format(query, response.content)
            )
        data = json.loads(response.content)
        if max_results:
            return data['issues']

        total_results = int(data['total'])
        max_results = int(data['maxResults'])
        remaining = total_results - max_results
        while remaining > 0:
            payload = {'jql': query,
                       'startAt': '{0}'.format(total_results - remaining)}
            response = self.rest_post(AtlassianUtils.JIRA_QUERY_URL, payload=payload)
            data['issues'].extend(json.loads(response.content)['issues'])
            remaining -= max_results

        return data['issues']

    def jira_get_defects_indirectly_fixed_references(self, devices=None):
        """
        Return the JIRA defects referenced by the resolution text of Resolved [Fixed Indirectly] JIRA defects
        :param devices: A list of devices to which to match the Fix Version(s) value of the Resolved JIRA defects
        :return: a map <indirectly_fixed_jira_defect, list of referenced jira_defects in resolution text>
        """

        filters = dict()
        filters['status'] = ['Resolved']
        filters['resolution'] = ['"Fixed No Action Taken"']

        if devices is not None:
            values = []
            for device in devices:
                values.append('versionMatch("{0}")'.format(device))
            filters['fixVersion'] = values

        jql_result = self.jira_get_defects_by_filters(filters)

        exception_messages_issued_by_invalid_defect_ids = list()
        defect_ids_content_exception_mapping = list()
        defect_id_exception_message = ''
        content_exception_message = ''
        result = dict()

        for item in jql_result:
            try:
                defect_id = item['key']
                print('Processing Defect ID {0}'.format(defect_id))
            except Exception as e:
                exception_messages_issued_by_invalid_defect_ids.append(str(e))
                continue

            try:
                resolution_text = item['fields']['customfield_10401']
                if resolution_text is None:
                    print('JIRA ID {0} resolution text is empty. Nothing to seek for.'.format(defect_id))
                    continue

                pattern = '({0}-[0-9]+)'.format(self.project_key)
                print('Seeking for referenced JIRA IDs in the resolution text of JIRA defect {0} which is "{1}"'.
                      format(defect_id, resolution_text))
                defects = list(set(re.findall(pattern, resolution_text)))
                result[defect_id] = defects
            except Exception as e:
                defect_ids_content_exception_mapping.append({defect_id: str(e)})
                continue

        if exception_messages_issued_by_invalid_defect_ids:
            defect_id_exception_message = 'Invalid Defect IDs issued the following exception messages: {0}{1}'.format(
                exception_messages_issued_by_invalid_defect_ids, os.linesep)

        if defect_ids_content_exception_mapping:
            content_exception_message = 'Defect IDs having invalid content: {0}{1}'.format(
                defect_ids_content_exception_mapping, os.linesep)

        if exception_messages_issued_by_invalid_defect_ids or defect_ids_content_exception_mapping:
            raise Exception('{0}{1}{2}'.format(defect_id_exception_message, os.linesep, content_exception_message))

        return result

    def jira_get_defects_by_status(self, statuses):
        """
        Retrieves all defects from a given JIRA project having one of the given statuses
        :param statuses: Defects statuses filter, based on which to filter the JIRA defects
        :return: The list of JIRA defects info
        """

        return self.jira_get_defects_by_filter('status', statuses)

    def jira_get_defects_by_filter(self, filter_name, filter_values):
        """
        Retrieves all defects from a given JIRA project filtered by a given filter name and values
        :param filter_name: Filter name, corresponding to a JIRA defect field that can be used in JQL
        :param filter_values: Filter values
        :return: The list of filtered JIRA defects info
        """

        filters = dict()
        filters[filter_name] = filter_values

        return self.jira_get_defects_by_filters(filters)

    def jira_get_defects_by_filters(self, filters):
        """
        Retrieves all defects from a given JIRA project filtered by several filters
        :param filters: Filter names and values passed as a dictionary
        (e.g. {'Filter_name1': ['value1', 'value2']; 'Filter_name2': ['value3', 'value4'];} )
        The filters will be ANDed
        :return: The list of filtered JIRA defects info
        """

        query = 'project = {0}'.format(self.project_key)

        f = dict(filters)
        for f_name in f.keys():
            f_values = list(f[f_name])
            if not f_values:
                continue  # disregard empty filters

            query += ' AND {0} IN ('.format(f_name)
            for f_value in f_values:
                query += str(f_value) + ', '
            query = query[:-2]  # remove last ', ' token
            query += ')'

        return self.jira_run_query(query)


class BitbucketUtils(AtlassianUtils):

    def __init__(self, bitbucket_project_key, username, password):
        """
        :param bitbucket_project_key: the unique project key (e.g. Bitbucket)
        :param username: The username to use for any Atlassian, REST call based operations
        :param password: The (encoded) password to be used
        """

        super(BitbucketUtils, self).__init__(username, password)
        self.__bitbucket_project_key = bitbucket_project_key

    def project_key(self):
        """Get the Bitbucket project key"""

        return self.__bitbucket_project_key

    def bitbucket_get_all_items_from_repo(self, repo_slug, repo_key):
        """Get all items from a specific repo

        :param repo_slug: URL-friendly version of a repository name, generated by Bitbucket for use in the URL
        :param repo_key: Repo key
        :return: Yields every item from repo
        :raise RuntimeError if the repo could not be read
        """

        next_page_start = 0
        while True:
            url = AtlassianUtils.BITBUCKET_GET_FILES_URL.format(repo_slug, repo_key, next_page_start)

            response = self.rest_get(url)
            if response.status_code != HttpStatusCodes.SUCCESS_OK:
                raise RuntimeError(
                    'Cannot read repo "{0}" content: {1}'.format(
                        '{0}-{1}'.format(repo_slug, repo_key), response.content)
                )
            data = json.loads(response.content)

            children = data.get('children', {})
            values = children.get('values', [])

            for value in values:
                yield value

            if children['isLastPage']:
                break

            next_page_start = children['nextPageStart']

    def bitbucket_get_text_file_content(self, repo_slug, repo_key, file_path):
        """
        Get the content of a text file from a specific repo
        :param repo_slug: URL-friendly version of a repository name, generated by Bitbucket for use in the URL
        :param repo_key: Repo key
        :param file_path: path of the file in repo's context
        :return: The content of the file. Exception is raised in case file is binary
        """

        url = AtlassianUtils.BITBUCKET_GET_FILE_URL.format(repo_slug, repo_key, file_path)

        response = self.rest_get(url)
        if response.status_code != HttpStatusCodes.SUCCESS_OK:
            raise RuntimeError('Cannot read file from "{0}": {1}'.format(url, response.content))

        data = json.loads(response.content)
        # if file is not binary, the 'binary' key is not present in the JSON response, so we default the return to False
        if not Utils.is_text(data):
            raise Exception('File {0} is not a text file'.format(file_path))

        lines = data['lines']  # get the lines array
        content = ''
        for line in lines:
            # Each line in lines array has a key-value pair with 'text' as key and the actual content as value
            # Add a newline '\n' after each concatenation
            content = content + line['text'] + '\n'
        return content

    def bitbucket_get_tag(self, repo, tag, project_key=None):
        """Retrieves information of a given tag

        :param repo: Bitbucket repo containing the tag
        :param tag: Tag name to get info of
        :param project_key: Project hosting the repo in Git

        :return: A @BitbucketTag instance corresponding to the given tag, or None if the tag does not exist
        """

        # Ignore 'self.project_key' and use 'project_key' to avoid re-initialization for different projects
        project_key = project_key or self.project_key

        next_page_start = 0
        while True:

            url = AtlassianUtils.BITBUCKET_GET_TAGS_URL.format(project_key, repo, next_page_start)
            response = self.rest_get(url)
            if response.status_code != HttpStatusCodes.SUCCESS_OK:
                raise RuntimeError('Tag {0} info could not be read: {1}'.format(tag, response.content))

            data = json.loads(response.content)

            tags = data['values']
            for t in tags:
                if t['displayId'] == tag:
                    return BitbucketTag(t['displayId'], t['latestCommit'])

            if data['isLastPage']:
                break

            next_page_start = data['nextPageStart']

    def bitbucket_get_latest_tag(self, repo):
        """
        Retrieves the latest tag from a Bitbucket repo
        :param repo: Name of the BITBUCKET repository containing the tag
        :return: A @BitbucketTag instance corresponding to the latest tag set on the repo or None if no such tag exists
        """

        url = AtlassianUtils.BITBUCKET_GET_TAGS_URL.format(self.project_key, repo, 0)
        response = self.rest_get(url)
        if response.status_code != HttpStatusCodes.SUCCESS_OK:
            raise RuntimeError('Tags could not be read: {0}'.format(response.content))

        data = json.loads(response.content)

        tags = data['values']
        if not tags:
            return None

        return BitbucketTag(data['values'][0]['displayId'], data['values'][0]['latestCommit'])

    def bitbucket_tag(self, repo, branch, tag, check_tag=True, message=''):
        """
        Tag a BITBUCKET repository
        :param repo: Repo to be tagged
        :param branch: Branch where the tag start point is [i.e. the latest commit of that branch]
        :param tag: The tag name
        :param check_tag: Checks if the tag already exists and raises an Exception if so
        :param message: A message relevant for the tag
        """

        print(r'Tagging the {0}\{1} branch with tag {2}'.format(repo, branch, tag))

        if check_tag and self.bitbucket_get_tag(repo, tag):
            raise Exception('Tag {0} already exists on repo {1}'.format(tag, repo))

        if len(tag) > 100:
            raise Exception('Tag {0} is too long. The maximum length is 100 characters'.format(tag))

        payload = {
            'force': 'true',
            'message': message,
            'name': tag,
            'startPoint': branch,
            'type': 'ANNOTATED'
        }
        url = AtlassianUtils.BITBUCKET_SET_TAG_URL.format(self.project_key, repo)

        response = self.rest_post(url, payload=payload)
        if response.status_code != HttpStatusCodes.SUCCESS_OK:
            raise RuntimeError('Failed to set tag {0}: {1}'.format(tag, response.content))

    def bitbucket_get_latest_commit_of_branch(self, repo, branch):
        """
        Retrieves the latest commit hash from a branch
        :param repo: Name of the BITBUCKET repository where the branch will be sought for
        :param branch: Branch to retrieve the last commit from
        :return: The latest commit of the branch or None of there's no commit on the branch
        """

        next_page_start = 0
        while True:

            url = AtlassianUtils.BITBUCKET_GET_BRANCHES_PAGED_URL.format(self.project_key, repo, next_page_start)
            response = self.rest_get(url)
            if response.status_code != HttpStatusCodes.SUCCESS_OK:
                raise RuntimeError('Bitbucket repository {0} branches could not be read: {1}'.format(
                    repo, response.content)
                )
            data = json.loads(response.content)

            branches = data['values']
            for b in branches:
                if b['displayId'] == branch:
                    return b['latestCommit']

            if data['isLastPage']:
                break

            next_page_start = data['nextPageStart']

        print('A branch named {0} was not found'.format(branch))

    def bitbucket_get_next_commit(self, repo, commit_id):
        """
        Retrieves the next commit hash after a given commit hash
        :param repo: Name of the BITBUCKET repository where to seek the next commit
        :param commit_id: The commit hash after which to seek the next[newer] commit
        :return: The next commit after a commit or None if no such commit exists
        """

        previous_commit_id = None
        next_page_start = 0
        while True:
            url = AtlassianUtils.BITBUCKET_GET_COMMITS_URL.format(self.project_key, repo, next_page_start)
            response = self.rest_get(url)
            if response.status_code != HttpStatusCodes.SUCCESS_OK:
                raise RuntimeError(
                    'The next commit after commit {commit_id} from Bitbucket repository {repo} '
                    'could not be retrieved: {error}'.format(commit_id=commit_id, repo=repo, error=response.content)
                )

            data = json.loads(response.content)

            commits = data['values']
            for c in commits:
                if c['id'] == commit_id:
                    return previous_commit_id
                previous_commit_id = c['id']

            if data['isLastPage']:
                break

            next_page_start = data['nextPageStart']

        print('There is no next commit after commit {0} from Bitbucket repository {1}'.format(commit_id, repo))

    def bitbucket_get_next_commit_after_tag(self, repo, tag):
        """
        Retrieves the next commit hash after a given tag
        :param repo: Name of the BITBUCKET repository where to seek the commit
        :param tag: Tag which to seek the commit after
        :return: The next commit after a tag or None if such commit does not exist
        """

        try:
            return self.bitbucket_get_next_commit(repo, tag.latest_commit)
        except RuntimeError:
            print('Failed to get the next commit after the specified tag {0}'.format(tag.latest_commit))
            raise

    def bitbucket_get_next_commit_after_latest_tag(self, repo):
        """
        Retrieves the next commit hash after the latest tag of a given repo
        :param repo: Name of the BITBUCKET repository where to seek the commit
        :return: The next commit after the latest  tag or None if such commit does not exist
        """

        latest_tag = self.bitbucket_get_latest_tag(repo)
        if not latest_tag:
            raise RuntimeError('Could not get the latest tag for repo {0}'.format(repo))

        try:
            return self.bitbucket_get_next_commit_after_tag(repo, latest_tag)
        except RuntimeError:
            print('Failed to get the latest commit after the latest tag {0}'.format(latest_tag.latest_commit))
            raise

    def bitbucket_get_pull_request_change_set(self, repo, pr_id, path_filters=None):
        """
        Retrieves the change set [as an array of paths] of a pull request
        :param repo: Name of the BITBUCKET repository where to seek
        :param pr_id: Pull request id
        :param path_filters: A dictionary filter for the change set path elements.
        Dictionary [keys, values] must match the pull request changes REST call return format
        Examples:
        dict({'extension':'html'})
        dict({'extension':[html, xml]})
        dict({'extension':[*ml]})
        dict({'extension':[html, xml]}, {'name':[*report]})

        :return: List of changed files with filters [if defined] applied
        """

        change_set = []
        changes = []
        next_page_start = 0
        while True:
            url = AtlassianUtils.BITBUCKET_PULL_REQUEST_PAGED_CHANGES_URL.format(
                self.project_key, repo, pr_id, next_page_start
            )
            response = self.rest_get(url)
            if response.status_code != HttpStatusCodes.SUCCESS_OK:
                raise RuntimeError('Could not get change set for pull request {0}'.format(pr_id))

            data = json.loads(response.content)
            changes.extend(data['values'])

            if not data['values']:
                break

            if data['isLastPage']:
                break

            next_page_start = data['nextPageStart']

        for c in changes:
            if path_filters is None:
                change_set.append(c['path']['toString'])
            else:
                for k, v in path_filters.items():
                    if k not in c['path'].keys():
                        continue  # filter key is not defined in pull request change set keys -> skip it

                    token = c['path'][k]
                    # Either token matches a list element, or if not list, is identical match, or regex match
                    try:
                        if (isinstance(v, list) and token in v) \
                                or (not isinstance(v, list) and (token == v or re.match(v, token))):
                            change_set.append(c['path']['toString'])
                    except:  # noqa: E722
                        raise 'Not supported filter value type for filter key: {0}'.format(k)

        return change_set

    def bitbucket_get_pull_request_activities_wrapper(self, args):
        """
        Wrapper of `bitbucket_get_pull_request_activities` method
        :param args: list of arguments matching the arguments number of `bitbucket_get_pull_request_activities`
        :return: the pull request activities.
        """

        pr = args[0]
        repo = args[1]

        pr['activities'] = self.bitbucket_get_pull_request_activities(repo, pr['id'])
        return pr

    def bitbucket_get_pull_request_change_set_wrapper(self, args):
        """
        Wrapper of `bitbucket_get_pull_request_change_set` method
        :param args: list of arguments matching the arguments number of `bitbucket_get_pull_request_change_set`
        :return: the pull request in case it matches the change set filters, None otherwise.
        """

        pr = args[0]
        repo = args[1]
        branch = args[2]
        change_set_path_filters = args[3]
        newer_than_timestamp = args[4]

        if (branch is None or pr['toRef']['displayId'] == branch) and \
                (newer_than_timestamp is None or pr['createdDate'] > newer_than_timestamp) and \
                (self.bitbucket_get_pull_request_change_set(repo, pr['id'], change_set_path_filters)):
            return pr

    def bitbucket_get_changes(self, repo, branch):
        """
        Retrieves the changes from a branch (compared to the branching point)
        :param repo: Name of the BITBUCKET repository where to seek
        :param branch: Branch to retrieve the commits from
        :return: List of changed files
        """

        files_changed = []
        next_page_start = 0
        while True:
            url = AtlassianUtils.BITBUCKET_GET_CHANGES_URL.format(self.project_key,
                                                                  repo,
                                                                  branch,
                                                                  next_page_start)
            response = self.rest_get(url)
            if response.status_code != HttpStatusCodes.SUCCESS_OK:
                raise RuntimeError('Could not get changes for branch {0}'.format(branch))

            data = json.loads(response.content)
            changes = data['values']
            for c in changes:
                files_changed.append(c['path']['toString'])

            if data['isLastPage']:
                break

            if not data['values']:
                break

            next_page_start = data['nextPageStart']

        return files_changed

    def bitbucket_get_merge_targets_for_branch(self, repo, branch):
        """Gather target branches specified in pull requests given the source branch
        :param repo: Name of the BITBUCKET repository where to seek
        :param branch: Name of (source) branch
        :return: List of branch names targeted for merging, None if no pull request is found
        """

        try:
            pull_requests = self.bitbucket_get_pull_requests(repo, branch, 'OUTGOING', 'OPEN')
            if not pull_requests:
                return

            target_branches = [pr['toRef']['displayId'] for pr in pull_requests]
            return target_branches
        except RuntimeError:
            print('Error retrieving target branches for branch {1} based on pull requests in {0}'.format(repo, branch))
            raise

    def bitbucket_get_jira_ids_in_commits_range(self, repo, start_commit, end_commit, match_status=None,
                                                ignore_missing=False, with_counts=False):
        """Get the jira ids within the specified commit range
        https://docs.atlassian.com/bitbucket-server/rest/7.12.1/bitbucket-rest.html#idp222
        :param repo: The Bitbucket repo where to seek the commits
        :param start_commit: The start commit
        :param end_commit: The end commit
        :param match_status: A list of status based on which to filter the JIRA IDs
        :param ignore_missing: Specify whether missing commits will be ignored
        :param with_counts: Specify whether the total number of commits should be included
        If None, no filter will be applied
        :return: The range of JIRA defect IDs between the start and end commit. The JIRA ID is determined by
        analysing the commit messages
        """

        commits = []
        next_page_start = 0
        while True:
            url = AtlassianUtils.BITBUCKET_GET_COMMITS_RANGE_URL.format(
                self.project_key, repo, start_commit, end_commit, next_page_start
            )
            if ignore_missing:
                url = '{0}&ignoreMissing=true'.format(url)
            if with_counts:
                url = '{0}&withCounts=true'.format(url)
            response = self.rest_get(url)
            if response.status_code != HttpStatusCodes.SUCCESS_OK:
                raise RuntimeError(
                    'Could not get the commits within the specified range {0}-{1}'.format(start_commit, end_commit)
                )

            data = json.loads(response.content)
            commits.extend(data['values'])

            if data['isLastPage']:
                break

            next_page_start = data['nextPageStart']

        jira_utils = JiraUtils(self.project_key)
        id_dict = defaultdict(list)
        for c in commits:
            message = c['message']
            # Only merge commits are selected
            if message.startswith('Merge pull request #'):
                jira_ids = list(set(re.findall('({0}-[0-9]+)'.format(self.project_key), message)))
                for jira_id in jira_ids:
                    status = jira_utils.jira_get_defect_status(jira_id)  # convert from Unicode
                    id_dict[status].append(jira_id)
                    id_dict[status] = list(set(id_dict[status]))

        ret_list = list()
        if match_status:
            for status in match_status:
                ret_list.extend(id_dict[status])
        else:
            for v in id_dict.values():
                ret_list.extend(v)

        return ret_list

    def bitbucket_get_pull_requests(self, repo, branch, direction, status):
        """
        Retrieves all pull requests associated with a Bitbucket repo branch
        :param repo: Bitbucket repo
        :param branch: Bitbucket branch
        :param direction: INCOMING [reaching this branch] or OUTGOING [coming from the branch]
        :param status: MERGED, OPEN
        :return: The pull requests dictionary
        """

        next_page_start = 0
        pull_requests = []
        while True:
            url = AtlassianUtils.BITBUCKET_GET_PULL_REQUESTS_URL.format(
                self.project_key, repo, branch, direction, status, next_page_start
            )

            response = self.rest_get(url)
            if response.status_code != HttpStatusCodes.SUCCESS_OK:
                raise RuntimeError('Could not get the pull requests for branch {0}'.format(branch))

            data = json.loads(response.content)
            pull_requests.extend(data['values'])

            if data['isLastPage']:
                break

            next_page_start = data['nextPageStart']

        print('Found {0} pull requests on branch {1}/{2}'.format(len(pull_requests), repo, branch))
        return pull_requests

    def bitbucket_get_all_pull_requests(self, repo, direction, status):
        """
        Retrieves all pull requests associated with a Bitbucket repo
        :param repo: Bitbucket repo
        :param direction: direction relative to the specified repository; either INCOMING or OUTGOING
        :param status: MERGED, OPEN, DECLINED
        :return: The pull requests list
        """

        next_page_start = 0
        pull_requests = []
        while True:
            url = AtlassianUtils.BITBUCKET_GET_ALL_PULL_REQUESTS_URL.format(
                self.project_key, repo, direction, status, next_page_start
            )
            response = self.rest_get(url)
            if response.status_code != HttpStatusCodes.SUCCESS_OK:
                raise RuntimeError('Could not get pull requests for repo {0}'.format(repo))

            data = json.loads(response.content)
            pull_requests.extend(data['values'])

            if data['isLastPage']:
                break

            next_page_start = data['nextPageStart']

        print('Found {0} pull requests on repo {1}'.format(len(pull_requests), repo))
        return pull_requests

    def bitbucket_get_pull_request_activities(self, repo, pr_id):
        """
        Retrieves a pull request detailed activity info
        :param repo: Bitbucket repo
        :param pr_id: pull request id
        :return: The pull requests activity
        """

        next_page_start = 0
        activities = []
        while True:
            url = AtlassianUtils.BITBUCKET_GET_PULL_REQUEST_ACTIVITY_URL.format(
                self.project_key, repo, pr_id, next_page_start)
            response = self.rest_get(url)
            if response.status_code != HttpStatusCodes.SUCCESS_OK:
                raise RuntimeError('Could not get activity info for pull request {0}'.format(pr_id))

            data = json.loads(response.content)
            activities.extend(data['values'])

            if data['isLastPage']:
                break

            next_page_start = data['nextPageStart']

        return activities

    def bitbucket_get_pull_request_info(self, repo, pr_id):
        """Get info about pull request info
        :param repo: Bitbucket repo
        :param pr_id: The pull request id
        """

        url = AtlassianUtils.BITBUCKET_PULL_REQUEST_INFO_URL.format(self.project_key, repo, pr_id)
        response = self.rest_get(url)
        if response.status_code != HttpStatusCodes.SUCCESS_OK:
            raise RuntimeError('Could not get info for pull request {0}'.format(pr_id))

        return json.loads(response.content)

    def bitbucket_get_pull_request_merge_info(self, repo, pr_id):
        """Get merge information for a pull request
        :param repo: Bitbucket repo
        :param pr_id: pull request id
        """

        url = AtlassianUtils.BITBUCKET_PULL_REQUEST_MERGE_URL.format(self.project_key, repo, pr_id)
        response = self.rest_get(url)
        if response.status_code != HttpStatusCodes.SUCCESS_OK:
            raise RuntimeError('Could not get merge info for pull request {0}'.format(pr_id))

        data = json.loads(response.content)

        pr_info_response = namedtuple('response', ['can_be_merged', 'has_conflicts', 'vetoes'])

        return pr_info_response(
            can_be_merged=data['canMerge'],
            has_conflicts=data['conflicted'],
            vetoes=[veto['detailedMessage'] for veto in data['vetoes']]
        )

    def bitbucket_merge_pull_request(self, repo, pr_id):
        """Get merge information for a pull request
        :param repo: Bitbucket repo
        :param pr_id: pull request id
        """

        pr_info = self.bitbucket_get_pull_request_info(repo, pr_id)

        url = '{url}?version={version}'.format(
            url=AtlassianUtils.BITBUCKET_PULL_REQUEST_MERGE_URL.format(self.project_key, repo, pr_id),
            version=pr_info['version']
        )
        response = self.rest_get(url)
        if response.status_code != HttpStatusCodes.SUCCESS_OK:
            raise RuntimeError('Could not merge pull request {0}'.format(pr_id))

    def bitbucket_get_randomized_default_tester(self, repo):
        """
        Determine a random default tester ID to be used when transitioning a JIRA ticket from Resolved to In Test state.
        The tester ID has to be valid, therefore it will be one of the reviewers of the latest merged pull request
        from the given repo.
        :param repo: repo name
        :return: Tester ID
        """

        pull_requests = self.bitbucket_get_all_pull_requests(repo, 'OUTGOING', 'MERGED')
        if not pull_requests:
            raise Exception('Default tester [i.e. one of the reviewers from the latest merged pull request ] '
                            'cannot be determined for repo {0}. '
                            'At least one merged pull request must exists in that repo'.format(repo))

        pr = pull_requests[0]  # this is the latest pull request from the given repo

        # choose a random reviewer from the pull request reviewers and return its ID
        index = randrange(0, len(pr['reviewers']))
        return pr['reviewers'][index]['user']['name']

    def bitbucket_get_code_review_statistics(self, repo, branch=None, change_set_path_filters=None,
                                             newer_than_timestamp=None):
        """
        Get statistics of code review done via pull requests
        :param repo: The BITBUCKET repo for which to get the statistics
        :param branch: The branch into which the pull requests were merged. If None, the entire `repo` will be evaluated
        :param change_set_path_filters: A dictionary filter for the pull requests change set path elements.
        Dictionary [key, value] must match the pull request changes REST call return format
        Examples:
        dict({'extension':'html'})
        dict({'extension':[html, xml]})
        dict({'extension':[*ml]})
        dict({'extension':[html, xml]}, {'name':[*report]})
        :param newer_than_timestamp: Analyze pull requests whose creation date is newer than a given date
        :return: A `ReviewStatistics` instance
        """

        pull_requests = self.bitbucket_get_all_pull_requests(repo, 'OUTGOING', 'MERGED')

        # using multi-threading to speed up pull requests analysis
        pool = ThreadPool(max(cpu_count(), 2))

        print('Fetching pull requests ...')
        prs = pool.map(self.bitbucket_get_pull_request_change_set_wrapper,
                       itertools.izip(pull_requests,
                                      itertools.repeat(repo),
                                      itertools.repeat(branch),
                                      itertools.repeat(change_set_path_filters),
                                      itertools.repeat(newer_than_timestamp)))

        valid_prs = [pr for pr in prs if pr]

        print('Fetching pull requests activities...')
        prs_with_activities = pool.map(self.bitbucket_get_pull_request_activities_wrapper,
                                       itertools.izip(valid_prs,
                                                      itertools.repeat(repo)))

        return ReviewStatistics(prs_with_activities)

    def bitbucket_get_code_review_statistics_for_source_code(self, repo, branch=None):
        """
        Get statistics of code review done via pull requests whose change set contains source code files
        :param repo: The BITBUCKET repo for which to get the statistics
        :param branch: The BITBUCKET branch for which to get the statistics. If None, the entire `repo` will be
                       evaluated
        :return: A `ReviewStatistics` instance
        """

        filters = dict({'extension': Utils.get_known_source_code_file_extensions()})
        return self.bitbucket_get_code_review_statistics(repo, branch, change_set_path_filters=filters)

    def bitbucket_get_referenced_jira_defects_in_merged_pull_requests(self, repo, branch):
        """
        Get all JIRA defects referenced in the merged pull requests associated with a branch
        :param repo: Bitbucket repo
        :param branch: Bitbucket branch
        :return: A list containing JIRA defects referenced by the merged pull requests
        """

        jira_list = []
        pull_requests = self.bitbucket_get_pull_requests(repo, branch, 'INCOMING', 'MERGED')
        for pr in pull_requests:
            # seek JIRA IDs in pull request's branch [from where it was merged] name, title and description
            seek_in_list = [pr['fromRef']['id'], pr['title'], pr['description'] if 'description' in pr.keys() else None]
            for seek_in in seek_in_list:
                if seek_in is not None:
                    jira_list.extend(list(set(re.findall('({0}-[0-9]+)'.format(self.project_key), seek_in))))

        return list(set(jira_list))  # remove duplicates

    def bitbucket_verify_moderator_in_pull_request(self, repo, pull_request):
        """
        Verifies if a pull request contains a moderator [different than the author] and if not sets one from among the
        reviewers.
        :param repo: repo to which the pull request belongs to
        :param pull_request: pull request to analyze
        :return: Pull request is compliant with moderator rules
        """

        reviewers = dict()
        for r in pull_request['reviewers']:
            reviewers[r['user']['name']] = r['user']['displayName']

        id_ = pull_request['id']
        #  the pull request may not have any description so we default it to empty
        description = pull_request['description'] if 'description' in pull_request.keys() else ''
        version = pull_request['version']
        number_of_reviewers = len(reviewers.items())

        if number_of_reviewers == 0:
            print('Pull request {0} does not have any reviewers'.format(id_))
            return False

        # the moderator [whether already set or about to be set] will be from among the reviewers
        # and will not be considered when determining the review type
        number_of_reviewers_other_than_moderator = number_of_reviewers - 1

        moderator_is_set = False
        print('Checking if pull request {0} has the moderator already set from among the reviewers'.format(id_))
        for reviewer in reviewers.keys():
            regex = '.*[' + os.linesep + ']*' + r'Moderator\s*=\s*@\s*' + reviewer
            print('Checking if reviewer [id: {0}, name:{1}] is set as moderator'.format(reviewer, reviewers[reviewer]))
            if re.match(regex, description, re.IGNORECASE | re.MULTILINE):
                print('Pull request {0} has a valid moderator set to {1}'.format(id_, reviewers[reviewer]))
                moderator_is_set = True
                break

        review_type_is_set = False
        # a dictionary containing the minimum number of reviewers [other than moderator or author] per review type
        review_types = dict([('Mini-walkthrough', 0), ('Walkthrough', 1), ('Inspection', 2)])
        set_review_type = None
        print('Checking if pull request {0} has the correct review type already set'.format(id_))
        for review_type in review_types.keys():
            regex = '.*[' + os.linesep + ']*' + r'Review type\s*=\s*' + review_type
            expected_numbers_of_reviewers = review_types[review_type]
            # make sure the review type is set properly, otherwise consider that the review type was not set
            if re.match(regex, description, re.IGNORECASE):
                set_review_type = review_type  # store the set review type
                review_type_is_set = (number_of_reviewers_other_than_moderator == expected_numbers_of_reviewers) or \
                                     (number_of_reviewers_other_than_moderator > 2 and review_type == 'Inspection')
                if review_type_is_set:
                    print('Pull request {0} has a valid review type set to {1}'.format(id_, set_review_type))

                break

        # add to the description header if necessary, the moderator name and review type
        description_header = ''
        if not moderator_is_set:
            # wipe out any garbage Moderator = XYZ from the pull request description,
            # because the moderator will be set automatically in the pull request description header
            regex = re.compile(r"Moderator\s*=\s*@?\S*", re.IGNORECASE | re.MULTILINE)
            description = regex.sub('', description)

            # set the moderator in the pull request description header
            moderator = reviewers.items()[0]  # the first reviewer is chosen to be the moderator
            print('Pull request {0} does not have a moderator. Attempting to set it to: {1}'.format(id_, moderator[1]))
            description_header += 'Moderator = @{0}{1}'.format(moderator[0], os.linesep)

        if not review_type_is_set:
            # wipe out any garbage Review type = XYZ from the pull request description,
            # because the review type will be set automatically in the pull request description header
            regex = re.compile(r"Review type\s*=\s*\S*", re.IGNORECASE | re.MULTILINE)
            description = regex.sub('', description)

            review_type_name = ''
            # determine the review type based on numbers of reviewers [other than moderator]
            for review_type in review_types.keys():
                if number_of_reviewers_other_than_moderator == review_types[review_type]:
                    review_type_name = review_type

            # in case the reviewers [others than moderator] exceed 2, the review type is Inspection
            if number_of_reviewers_other_than_moderator > 2:
                review_type_name = 'Inspection'

            if set_review_type is None:
                print(
                    'Pull request {0} does not have the review type set. Attempting to set it to: {1}'.format(
                        id_, review_type_name)
                )
            else:
                print(
                    'Pull request {0} has the review type incorrectly set to {1}. Attempting to set it to: {2}'.format(
                        id_, set_review_type, review_type_name)
                )

            description_header += 'Review type = {0}{1}'.format(review_type_name, os.linesep)

        # if there is anything to add to description header [moderator, review type of both],
        # then add it at the beginning of the pull request description
        if description_header != '':
            payload = dict()
            # the version [identical to current version of the pull request] is mandatory
            # when changing the pull request attributes
            payload['version'] = version
            # TODO: cosmetic improvement: set moderator always before the description for consistency's sake
            payload['description'] = description_header + description.strip()
            # reviewers must be set each time the pull request changes, otherwise they'll be automatically removed
            payload['reviewers'] = pull_request['reviewers']

            url = AtlassianUtils.BITBUCKET_PULL_REQUEST_INFO_URL.format(self.project_key, repo, id_)
            response = self.rest_put(url, payload=payload)
            if response.status_code != HttpStatusCodes.SUCCESS_OK:
                print('Adding {0} to pull request id {1} failed'.format(description_header, id_))
                return False

        return True

    def bitbucket_verify_moderators_in_pull_requests(self, repo, branch, direction, status):
        """
        Verifies if all pull requests associated with a Bitbucket branch are compliant with moderator rules
        :param repo: repo to seek in
        :param branch: branch to seek in
        :param direction: pull request direction
        :param status: pull request status
        :return: True if full compliance with moderator rules, False otherwise
        """

        print('Checking if the pull requests from branch {0}/{1} have a moderator properly set'.format(repo, branch))
        pull_requests = self.bitbucket_get_pull_requests(repo, branch, direction, status)
        if not pull_requests:
            raise Exception('No {0} pull request exists for branch {1}/{2}'.format(status, repo, branch))

        result = True
        for pr in pull_requests:
            result &= self.bitbucket_verify_moderator_in_pull_request(repo, pr)

        if not result:
            raise Exception('Some {0} pull requests from branch {1}/{2} have the moderators identical to the authors'
                            .format(status, repo, branch))

    def bitbucket_get_pull_requests_tasks_info(self, repo, branch, direction, status):
        """
        Retrieves a [pull_request_id, number of resolved tasks] map
        :param repo: repo to seek in
        :param branch: branch to seek in
        :param direction: pull request direction
        :param status: pull request status
        :return: tasks per pull requests map
        """

        tasks = dict()
        pull_requests = self.bitbucket_get_pull_requests(repo, branch, direction, status)
        for pr in pull_requests:
            tasks[pr['id']] = pr['properties']['resolvedTaskCount']

        return tasks

    def bitbucket_delete_repo_branch(self, repo, branch):
        """Delete a bitbucket repository branch
        :param repo: repo to delete branch from
        :param branch: branch to be deleted
        """

        url = AtlassianUtils.BITBUCKET_GET_BRANCHES_URL.format(self.project_key, repo)
        payload = {
            "name": branch,
            "dryRun": False
        }

        response = self.rest_delete(url, payload=payload)
        if response.status_code != HttpStatusCodes.SUCCESS_NO_CONTENT:
            raise RuntimeError('Could not delete branch {0} from repo {1}'.format(branch, repo))


class BambooUtils(AtlassianUtils):
    """Bamboo utils class."""

    class BambooQueryTypes:

        def __init__(self):
            pass

        TRIGGER_PLAN_QUERY = 0
        STOP_PLAN_QUERY = 1
        RESULTS_QUERY = 2
        PLAN_QUERY = 3
        QUEUE_QUERY = 4
        ARTIFACT_QUERY = 5

        KNOWN_QUERY_TYPES = range(6)

    def __init__(self, bamboo_project_key, username, password):
        """
        :param bamboo_project_key: the unique project key (e.g. Bamboo)
        :param username: The username to use for any Atlassian, REST call based operations
        :param password: The (encoded) password to be used
        """

        super(BambooUtils, self).__init__(username, password)
        self.__bamboo_project_key = bamboo_project_key
        self.__query_types = BambooUtils.BambooQueryTypes
        self.__bamboo_server = self.get_bamboo_server()
        self.__bamboo_branch_name = self.get_bamboo_branch_name()

    def project_key(self):
        """Get the Bamboo project key"""

        return self.__bamboo_project_key

    @property
    def query_types(self):
        """Return the query types"""

        return self.__query_types

    @property
    def bamboo_server(self):
        """Return the coverity server"""

        return self.__bamboo_server

    @property
    def bamboo_branch_name(self):
        """Return the coverity server"""

        return self.__bamboo_branch_name

    @staticmethod
    def get_artifacts_from_html_page(page_content):
        """Parses HTML page in order to obtain the list of artifacts.
        :param page_content: HTML page content
        """

        artifacts = list()

        soup = BeautifulSoup(page_content, 'html.parser')
        # All "<a href></a>" elements
        a_html_elements = (soup.find_all('a'))

        for a_html_elem in a_html_elements:
            # File name, as href tag value
            file_name = a_html_elem.extract().get_text()

            # Do not add HREF value in case PAGE NOT FOUND error
            if file_name != "Site homepage":
                artifacts.append(file_name)

            # TODO: add support to download artifacts from sub-dirs as well

        return artifacts

    def get_bamboo_server(self):
        """Get the bamboo server from 'bamboo_resultsUrl' plan variable
        e.g: bamboo_resultsUrl=https://bamboo1.sw.nxp.com/browse/AMPAT-XYZ-XYZ1-1 --> bamboo1"""

        results_url = self.get_bamboo_env('resultsUrl')
        server_name = None
        try:
            extract_instance = extract(results_url)
            sub_domain = extract_instance[0]
            server_name = sub_domain.split('.')[0]
        except Exception as exc:  # noqa: E722
            print("{0}Could not get Bamboo server name: {1}".format(os.linesep, exc))

        print("{0}INFO: Running on Bamboo server: '{1}'".format(os.linesep, server_name))

        return server_name

    def get_bamboo_branch_name(self):
        """Get the bamboo branch name from 'bamboo_planName' plan variable
        e.g: bamboo_planName=ARTD - Nightly - BLN_RTD_4.4_S32K1XX_0.8.0 --> branch name: BLN_RTD_4.4_S32K1XX_0.8.0"""

        plan_name = self.get_bamboo_env('planName')
        branch_name = None
        try:
            branch_name = plan_name.split('-')[2].strip()
        except Exception as exc:  # noqa: E722
            print("{0}Could not get Bamboo branch name: {1}".format(os.linesep, exc))

        print("{0}INFO: Current Bamboo branch name is: '{1}'".format(os.linesep, branch_name))

        return branch_name

    def create_url(self, query_type, build_key=None, job=None, artifact=None, url_query_string=None):
        """Dynamically create a URL based on provided arguments.
        :param query_type: The type of query used to create the url (a type listed in BambooQueryTypes)
        :param build_key: The bamboo build key (optional)
        :param job: The job name as configured in bamboo (optional)
        :param artifact: The artifact to be used (optional)
        :param url_query_string: The query string to be used (optional)
        """

        if query_type not in self.query_types.KNOWN_QUERY_TYPES:
            raise ValueError("Query type: '{0}' not supported!".format(query_type))

        if query_type == self.query_types.TRIGGER_PLAN_QUERY:
            return "{url}{build_key}.json".format(
                url=AtlassianUtils.BAMBOO_TRIGGER_PLAN_URL.format(self.bamboo_server),
                build_key=build_key
            )

        elif query_type == self.query_types.PLAN_QUERY:
            return "{url}{build_key}.json?includeAllStates=true".format(
                url=AtlassianUtils.BAMBOO_QUERY_PLAN_URL.format(self.bamboo_server),
                build_key=build_key
            )

        elif query_type == self.query_types.RESULTS_QUERY:
            return "{url}{build_key}.json?max-results=10000".format(
                url=AtlassianUtils.BAMBOO_PLAN_RESULTS_URL.format(self.bamboo_server),
                build_key=build_key
            )

        elif query_type == self.query_types.STOP_PLAN_QUERY:
            return "{url}?planResultKey={build_key}".format(
                url=AtlassianUtils.BAMBOO_STOP_PLAN_URL.format(self.bamboo_server),
                build_key=build_key
            )

        elif query_type == self.query_types.QUEUE_QUERY:
            return "{url}?expand=queuedBuilds".format(
                url=AtlassianUtils.BAMBOO_LATEST_QUEUE_URL.format(self.bamboo_server)
            )

        elif query_type == self.query_types.ARTIFACT_QUERY:
            url_query_string = url_query_string or ''
            return (
                "{url}{url_query_string}".format(
                    url=AtlassianUtils.BAMBOO_ARTIFACT_URL.format(
                        self.bamboo_server, build_key, job, artifact
                    ),
                    url_query_string=url_query_string)
            )

    def bamboo_trigger_build(self, build_key=None, req_values=None):
        """Method to trigger a build using Bamboo API

        :param build_key: Bamboo build key [string]
        :param req_values: Values to insert into request (tuple)

        :return: A named tuple containing HTTP status_code and request content
        :raise: Exception, ValueError on Errors
        """

        if not all((self.bamboo_server, build_key)):
            return {'content': "Incorrect input provided!"}

        # Execute all stages by default if no options received
        payload = {'stage&executeAllStages': [True]}
        # req_values[0] = True/False
        if req_values:
            payload['stage&executeAllStages'] = [req_values[0]]

            # Example
            # req_value[1] = {'bamboo.driver': "xyz", bamboo.test': "xyz_1"}
            # API supports a list as values
            for key, value in req_values[1].iteritems():
                payload[key] = [value]

        url = self.create_url(self.query_types.TRIGGER_PLAN_QUERY, build_key=build_key)
        print("{0}URL used to trigger build: '{1}'".format(os.linesep, url))

        response = self.rest_post(url, payload=payload)
        if response.status_code != HttpStatusCodes.SUCCESS_OK:
            raise RuntimeError("Could not trigger build for plan {0}, request content: '{1}'".format(
                build_key, response.content))

        return response

    def bamboo_query_build(self, build_key):
        """Method to query a plan build using Bamboo API.

        :param build_key: Bamboo build key [string]

        :return: A named tuple containing HTTP status_code and request content
        :raise: Exception, ValueError on errors
        """

        url = self.create_url(self.query_types.RESULTS_QUERY, build_key=build_key)
        print("{0}URL used in query: '{1}'".format(os.linesep, url))

        response = self.rest_get(url)
        if response.status_code != HttpStatusCodes.SUCCESS_OK:
            raise RuntimeError("Could not query plan build having build key {0}, request content: '{1}'".format(
                build_key, response.content))

        return response

    def bamboo_query_build_for_artifacts(self, build_key=None, job=None, artifact=None, url_query_string=None):
        """Method to query Bamboo plan run for stage artifacts

        :param build_key: Bamboo build key [string]
        :param job: Bamboo plan job name [string]
        :param artifact: Name of the artifact as in Bamboo plan stage job [string]
        :param url_query_string: Query string to compound the URL [string]

        :return: A list containing the artifacts found in the response data
        :raise: Exception, ValueError on Errors
        """

        if not all((build_key, job, artifact)):
            return {'content': "Incorrect input provided!"}

        url = self.create_url(self.query_types.ARTIFACT_QUERY, build_key=build_key, job=job, artifact=artifact,
                              url_query_string=url_query_string or '')
        print("{0}URL used to query for artifacts: '{1}'".format(os.linesep, url))

        response = self.rest_get(url)
        if response.status_code != HttpStatusCodes.SUCCESS_OK:
            raise RuntimeError("Could not query plan build having build key {0} for artifacts, request content: '{1}'".
                               format(build_key, response.content))

        return self.get_artifacts_from_html_page(response.content)

    def bamboo_get_artifact(self, build_key=None, job=None, artifact=None, url_query_string=None,
                            destination_file=None):
        """Method to download artifact from Bamboo plan

        :param build_key: Bamboo build key [string]
        :param job: Bamboo plan job name [string]
        :param artifact: Name of the artifact as in Bamboo plan stage job [string]
        :param url_query_string: Query string to compound the URL [string]
        :param destination_file: Full path to destination file [string]

        :return: A named tuple containing HTTP status_code and request content
        :raise: Exception, ValueError on Errors
        """

        if not all((build_key, job, artifact, destination_file)):
            return {'content': "Incorrect input provided!"}

        url = self.create_url(self.query_types.ARTIFACT_QUERY, build_key=build_key, job=job, artifact=artifact,
                              url_query_string=url_query_string or '')
        print("{0}URL used to download artifact: '{1}'".format(os.linesep, url))

        response = self.rest_get(url, destination_file=destination_file)
        if response.status_code != HttpStatusCodes.SUCCESS_OK:
            raise RuntimeError("Could not get the requested artifact {0}, request content: '{1}'".format(
                artifact, response.content))

        return response

    def bamboo_stop_build(self, build_key=None):
        """Method to stop a running plan from Bamboo using Bamboo API

        :param build_key: Bamboo build key [string]

        :return: A named tuple containing HTTP status_code and request content
        :raise: Exception, ValueError on errors
        """

        if not build_key:
            return {'content': "Incorrect input provided!"}

        url = self.create_url(self.query_types.STOP_PLAN_QUERY, build_key=build_key)
        print("{0}URL used to stop plan: '{1}'".format(os.linesep, url))

        response = self.rest_post(url)
        if response.status_code != HttpStatusCodes.REDIRECT_FOUND:
            raise RuntimeError("Could not stop build for plan having build key {0}, request content: '{1}'".format(
                build_key, response.content))

        return response

    def bamboo_kill_build_after_timeout(self, kill_after_timeout=-1, build_key=None):
        """Method to watch an Job execution on Bamboo stage.
        If exceed the specified timeout, the method will stop the current plan

        :param kill_after_timeout: Timeout interval to wait until stopping the plan (seconds) [integer]
        :param build_key: Bamboo build key [string]

        :return Thread
                None, no 'build_key/kill_after_timeout' supplied
        """

        if kill_after_timeout == -1:
            print("{0}Aborting the execution of the method as 'kill_after_timeout = -1'!{0}".format(os.linesep))
            return None

        if not build_key:
            print("{0}No build key supplied!{0}".format(os.linesep))
            return None

        kill_timeout = float(kill_after_timeout)

        print(
            "{0}Watching the current Bamboo JOB under plan '{1}' for a timeout period of: '{2}' seconds{0}".format(
                os.linesep,
                build_key,
                kill_timeout
            )
        )
        kill_timer = threading.Timer(kill_timeout, self.bamboo_stop_build, [build_key])
        kill_timer.start()

        return kill_timer

    def bamboo_get_plan_branch(self, plan_key, branch_name):
        """Retrieves the specified branch of the given Bamboo plan
        :param plan_key: plan key in form {projectKey}-{buildKey}
        :param branch_name: name of branch
        :return branch details
        """

        # noinspection PyBroadException
        url = AtlassianUtils.BAMBOO_PLAN_BRANCH_REQUEST_URL.format(plan_key, branch_name)
        response = self.rest_get(url)
        if response.status_code != HttpStatusCodes.SUCCESS_OK:
            raise RuntimeError("Could not get info for plan branch {0}, request content: '{1}'".format(
                branch_name, response.content))

        return response

    def bamboo_get_branch_key_by_name(self, plan, plan_branch):
        """Gets the branch unique id if the name is found in the configured plan branches
        :param plan: plan unique key
        :param plan_branch: name of the branch
        :return: branch unique key in the plan, if it is configured
        """

        request_url = AtlassianUtils.BAMBOO_GET_PLAN_BRANCHES_INFO_URL.format(self.bamboo_server, plan)

        response = self.rest_get(request_url)
        if response.status_code != HttpStatusCodes.SUCCESS_OK:
            raise RuntimeError("Could not get branch key for plan branch {0}, request content: '{1}'".format(
                plan_branch, response.content))

        # check whether branch is configured in the plan
        branch_key = None
        for branch_info in json.loads(response.content)['branches']['branch']:
            if plan_branch == branch_info["shortName"]:
                branch_key = branch_info["key"]
                break

        if not branch_key:
            raise RuntimeError(
                "Branch {0} is not configured in the plan: {1}, please create the plan branch".format(plan_branch, plan)
            )

        return branch_key

    def bamboo_wait_for_build(self, build_url, timeout=0):
        """Waits for a specific build to be finished using get requests and interrogating build status.
        :param build_url: Triggered build url
        :param timeout: Maximum build time for triggered build until the build is considered to be failed, in seconds,
        if 0, the build will be left to run indefinitely
        """

        start = time.time()
        while True:
            if timeout and time.time() - start > timeout:
                raise Exception("Triggered build took longer than the configured time {0}".format(timeout))

            response = self.rest_get(build_url)
            if response.status_code != HttpStatusCodes.SUCCESS_OK:
                raise RuntimeError("Could not query build at {0}, request content: '{1}'".format(
                    build_url, response.content))

            build_status = json.loads(response.content)["buildState"]
            if build_status != "Unknown":
                break
            else:
                print(
                    "{0}Triggered build is still running, waiting 60 more seconds for build completion".format(
                        os.linesep)
                )
            time.sleep(60)

        if build_status == "Failed":
            raise RuntimeError("Triggered build failed. Please check {0} for logs".format(build_url))
        else:
            print("{0}Triggered build was successful".format(os.linesep))

    def bamboo_build_plan_branch(self, plan_settings, wait_completion=True, timeout=0):
        """Triggers a build in the configured plan.
        :param plan_settings: configuration instance of the remote plan containing information about plan name, branch
        name and build arguments
        :param wait_completion: boolean determining whether the build result will be waited
        :param timeout: Maximum build time for triggered build until the build is considered to be failed, in seconds,
        if 0, the build will be left to run indefinitely
        """

        request_url = AtlassianUtils.BAMBOO_QUEUE_POST_REQUEST_URL.format(
            self.bamboo_server,
            self.bamboo_get_branch_key_by_name(
                plan_settings.plan, plan_settings.plan_branch
            ) + ".json?"
        )
        if plan_settings.build_args:
            request_url += plan_settings.build_args

        # create a dictionary using key:[list], if not already formatted from the caller
        request_data = dict()
        for key in plan_settings.bamboo_build_args:
            if type(plan_settings.bamboo_build_args[key]) is not list:
                request_data[key] = [plan_settings.bamboo_build_args[key]]
            else:
                request_data[key] = plan_settings.bamboo_build_args[key]

        response = self.rest_post(request_url, payload=request_data)
        if response.status_code != HttpStatusCodes.SUCCESS_OK:
            raise RuntimeError("Could not trigger build at {0}, request content: '{1}'".format(
                request_url, response.content))

        Utils.print_with_header("Build Triggered: {0}".format(request_url))

        if wait_completion:
            self.bamboo_wait_for_build(json.loads(response.content)["link"]["href"] + ".json", timeout)

    def bamboo_trigger_build_plan(self, build_plan_key):
        """Post the specified build to the Bamboo build queue
        :param build_plan_key: Build plan key
        """

        print(
            '{0}Posting build plan to Bamboo queue: https://{1}.sw.nxp.com/browse/{2}'.format(
                os.linesep,
                self.bamboo_server,
                build_plan_key
            )
        )

        url = AtlassianUtils.BAMBOO_QUEUE_POST_REQUEST_URL.format(self.bamboo_server, build_plan_key)
        self.rest_post(url, payload={})


class AutomationConfiguration(object):
    """Abstraction for the settings of an automation system."""

    # This is required to preserve backward compatibility where BambooSettings class members are accessed in a static
    # way, instead via an instance of the class. When all the plans will switch to using instance-based
    # access, the workaround will be removed
    static_instance = None

    @staticmethod
    def get_static_instance(plan_type='bamboo_'):
        """
        Return an AutomationConfiguration instance in order to facilitate the access to the settings of the automation
        system
        :param plan_type: The plan type of the automation system
        :return: An AutomationConfiguration instance
        """

        if not AutomationConfiguration.static_instance:
            AutomationConfiguration.static_instance = AutomationConfiguration(plan_type)

        return AutomationConfiguration.static_instance

    @staticmethod
    def initialize_groups(plan_type):
        """Return the tuple formed by repo name, slug and repo suffix
           e.g. for the ssh://git@bitbucket.sw.nxp.com/artd/base.git repository ('/artd/', 'base', '.git') would be
           the resulted tuple"""

        url = AtlassianUtils.get_env_var('planRepository_repositoryUrl', plan_type)

        # Check if the regex can be improved
        groups = re.search('(/[^.]*/)([^/]*)(\.git)', url).groups()
        if groups is None:
            raise Exception('Repository URL Bamboo variable does not have the expected format: {0}'.format(url))

        if len(groups) != 3:  # check that we're indeed dealing with an appropriate Bamboo variable
            raise Exception('Repo and project cannot be decoded from Bamboo variable {0}'.format(url))
        elif groups[2] != '.git':  # marker that we're dealing with a git repo
            raise Exception('Repo and project cannot be decoded from Bamboo variable {0}'.format(url))

        return groups

    def __init__(self, plan_type):

        # Plan type
        self._plan_type = plan_type

        # Groups
        self.__groups = AutomationConfiguration.initialize_groups(self._plan_type)

        # Project
        self._project = self.__groups[0].replace('/', '').upper()

        # Repository
        self._repo = self.__groups[1]

        # Product name
        self._product_name = AtlassianUtils.get_env_var('planRepository_name', self._plan_type)

        # Agent name
        self._agent_id = AtlassianUtils.get_env_var('capability_agent_id', self._plan_type)

        # Job name
        self._job = AtlassianUtils.get_env_var('shortJobName', self._plan_type)

        # Job key
        self._job_short_key = AtlassianUtils.get_env_var('shortJobKey', self._plan_type)

        # The Bamboo plan working directory passed as Bamboo variable
        self._working_dir = AtlassianUtils.get_env_var('build_working_directory', self._plan_type)

        # Plan name
        self._plan_name = AtlassianUtils.get_env_var('planName', self._plan_type)

        # plan branch name
        try:
            # e.g. bamboo_planName=ANFC - Continuous integration - _nightly_sdk_S32K144
            self._plan_branch_name = re.search(r"^(?:[^-]+-){2}\s*(.*)$", self._plan_name).groups()[0]
        except:  # noqa E722
            print("[plan_branch_name] failed to retrieve plan_branch_name from: {0}".format(self._plan_name))
            self._plan_branch_name = None

        # Short plan name
        self._short_plan_name = AtlassianUtils.get_env_var('shortPlanName', self._plan_type)

        # Plan key
        self._plan_key = AtlassianUtils.get_env_var('planKey', self._plan_type)

        # Stage key
        self._stage_key = AtlassianUtils.get_env_var('buildKey', self._plan_type)

        # Plan build number
        self._plan_build_number = AtlassianUtils.get_env_var('buildNumber', self._plan_type)

        # Build key
        self._build_key = '{0}-{1}'.format(self._plan_key, self._plan_build_number)

        # Suppress_errors
        self._suppress_errors = AtlassianUtils.get_boolean_bamboo_env('suppress_errors')

        # Path to the debug location
        self._debug_location = Utils.get_debug_location()

        # Product name
        product_name = AtlassianUtils.get_env_var('product_name', self.plan_type)

        if not product_name:
            self._debug_location = os.path.join(self._debug_location, self.plan_key)
        else:
            self._debug_location = os.path.join(self._debug_location, product_name.replace(' ', '_'))

        # Debug mode
        self._debug_mode = AtlassianUtils.get_boolean_bamboo_env('debug_mode')

        # List of jobs for which artifacts will not be deleted in case of errors
        # E.g HISW* - regex used to keep artifacts for all HIS workers
        # E.g HISC - keep only for HIS collector job
        # The examples mentioned above can be combined as HISW*, HISC
        self._keep_shared_artifacts_in_case_of_error_for_jobs = AtlassianUtils.get_list_from_bamboo_env_var(
            'keep_shared_artifacts_in_case_of_error_for_jobs'
        )

        self._keep_plan_shared_artifacts = any([
            re.match('^{0}$'.format(job), self.job_short_key)
            for job in self.keep_shared_artifacts_in_case_of_error_for_jobs
        ])

        AutomationConfiguration.static_instance = self

    @property
    def plan_type(self):
        """Get the plan type."""

        return self._plan_type

    @property
    def repo(self):
        """Get the repository."""

        return self._repo

    @property
    def project(self):
        """Get the project."""

        return self._project

    @property
    def agent_id(self):
        """Get the agent ID."""

        return self._agent_id

    @property
    def job(self):
        """Get the job name."""

        return self._job

    @property
    def product_name(self):
        """Get the product name."""

        return self._product_name

    @property
    def job_short_key(self):
        """Get the job key."""

        return self._job_short_key

    @property
    def working_dir(self):
        """Get the Bamboo plan working directory passed as Bamboo variable."""

        return self._working_dir

    @property
    def plan_name(self):
        """Get the plan name."""

        return self._plan_name

    @property
    def short_plan_name(self):
        """Get the short plan name."""

        return self._short_plan_name

    @property
    def plan_branch_name(self):
        """Get the branch name."""

        return self._plan_branch_name

    @property
    def plan_key(self):
        """Get the plan key."""

        return self._plan_key

    @property
    def stage_key(self):
        """Get the stage key."""

        return self._stage_key

    @property
    def plan_build_number(self):
        """Get the plan build number."""

        return self._plan_build_number

    @property
    def build_key(self):
        """Get the build key."""

        return self._build_key

    @property
    def suppress_errors(self):
        """Suppress errors."""

        return self._suppress_errors

    @property
    def debug_location(self):
        """Get the standardized debugging path for all releases."""

        return self._debug_location

    @property
    def debug_mode(self):
        """Debug mode."""

        return self._debug_mode

    @property
    def keep_shared_artifacts_in_case_of_error_for_jobs(self):
        """Get the the list of shared artifacts kept in case of error"""

        return self._keep_shared_artifacts_in_case_of_error_for_jobs

    @property
    def keep_plan_shared_artifacts(self):
        """The boolean value configured for keeping the plan shared artifacts"""

        return self._keep_plan_shared_artifacts

    @staticmethod
    def get_branches():
        """
        Abstract method that must be implemented in the classes that derives this class
        """

        raise NotImplementedError('Cannot call method {0} of abstract class {1} instance'
                                  .format(inspect.currentframe().f_code.co_name, 'AutomationConfiguration'))

    @staticmethod
    def get_content_from_config_file(config_file=None):
        """Read the config config file
        :param config_file: Configuration file [string]
        :return: file content [dict]
                 None, no config file supplied
        :raise ValueError
        """

        if not config_file:
            raise ValueError("\nNo config file supplied for reading!\n")

        file_type = os.path.splitext(config_file)[1].split(".")[1].lower()
        if not file_type:
            raise ValueError("\nNo file_type found for config file: {0}\n".format(config_file))

        if file_type == 'json':
            try:
                with open(config_file) as file_desc:
                    file_content = json.load(file_desc)
            except:  # noqa: E722
                raise ValueError("\nSomething went wrong when parsing the config file: {0}\n".format(config_file))

            if not file_content:
                raise ValueError("\nCould not get content from config file: {0}\n".format(config_file))

            return file_content

        return None


class BambooSettings(AutomationConfiguration):
    """
    Bamboo build settings
    """

    @staticmethod
    def get_branches():
        """Return the list of branches configured for current plan
        :return The list of branches
        """

        branches = []
        index = 1
        while True:
            env_var = AtlassianUtils.get_env_var('planRepository_{0}_branch'.format(index))
            index += 1
            if env_var is not None:
                branches.append(env_var)
            else:
                break

        return branches

    # This is required to preserve backward compatibility where BambooSettings class members are accessed in a static
    # way, instead via an instance of the class. When all the plans will switch to using instance-based
    # access, the workaround will be removed
    try:
        automation_configuration = AutomationConfiguration.get_static_instance()
        working_dir = automation_configuration.working_dir
        project = automation_configuration.project
        build_key = automation_configuration.build_key
        short_plan_name = automation_configuration.short_plan_name
        plan_branch_name = automation_configuration.plan_branch_name
        product_name = automation_configuration.product_name
        plan_key = automation_configuration.plan_key
        plan_build_number = automation_configuration.plan_build_number
        branches = get_branches.__func__()
        branch = branches[0]

    # In the case that the statements above fail, we can be sure that the current build system relies actually on
    # Jenkins. These static variables are not needed on a Jenkins build so the execution can continue without treating
    # the exception.
    except:  # noqa: E722
        pass

    def __init__(self, plan_type='bamboo_'):

        super(BambooSettings, self).__init__(plan_type)
        self._branches = BambooSettings.get_branches()
        self._branch = self._branches[0]
        self.__results_url = AtlassianUtils.get_bamboo_env('resultsUrl')

    @property
    def branches(self):
        """Get the current branches"""

        return self._branches

    @property
    def branch(self):
        """Get the main (first) configured branch"""

        return self._branch

    @property
    def results_url(self):
        """Get the results url"""

        return self.__results_url

    @property
    def server_name(self):
        """Get the bamboo server name from 'bamboo_resultsUrl' plan variable
        e.g: bamboo_resultsUrl=https://bamboo1.sw.nxp.com/browse/AMPAT-XYZ-XYZ1-1 --> bamboo1
        """

        if not self.results_url:
            return

        # extract("https://bamboo1.sw.nxp.com/browse/AMPAT-XYZ-XYZ1-1")
        # --> ExtractResult(subdomain='bamboo1.sw', domain='nxp', suffix='com')
        server_name = None
        try:
            extract_instance = extract(self.results_url)
            sub_domain = extract_instance[0]
            server_name = sub_domain.split('.')[0]
        except:  # noqa: E722
            print("Could not get Bamboo server name!")

        return server_name


class JIRAProject(object):
    """
    Abstraction for a JIRA project
    """
    def __init__(self, id_, schema):
        self.id_ = id_
        self.schema = schema


class JIRASchema(object):
    """
    Abstraction for the fields definition [UI_field_name, field_id] of a JIRA schema
    """
    def __init__(self):
        self.fields = dict()

    def get_field_id_by_name(self, name):
        """
        Get a JIRA defect field ID as defined by the schema from its corresponding name in web UI
        :param name: JIRA defect field name a it appears in web UI
        :return:The JIRA defect field ID as defined by the schema
        """

        if name in self.fields.keys():
            return self.fields[name]
        else:
            return None

    def get_field_name_by_id(self, field_id):
        """
        Get a JIRA defect field name as it appears in web UI from its corresponding id as defined by the schema
        :param field_id: JIRA defect field ID as defined by the schema
        :return:The JIRA defect field name as it appears in web UI
        """

        for key in self.fields.keys():
            if self.fields[key] == field_id:
                return key
        return None


class PullRequestTriggerJob(AutomationJob):
    """
    Base class for pull-requests monitoring jobs
    Subclasses only need to define product specific get_build_plan_key method
    """

    class PRTriggerState(object):
        """
        Helper class to maintain the state related to triggering builds for pull-requests
        State is recorded in a shared location database
        """

        DB_PATH = os.path.join(Utils.get_shared_resources_location(), 'Builds', 'S32SDK', 'pull_request_monitoring',
                               'trigger_state.db')

        def __init__(self):
            """State is maintained in the database as TABLE (PullRequestId, CommitId)
            signifying the most recent commit for which a build has been triggered for the specified pull request"""

            self.con = sqlite3.connect(self.DB_PATH)

        def get_known_pull_requests(self):
            """
            Retrieve all known pull requests
            :return: List of pull request ids
            """

            with self.con:
                cur = self.con.cursor()
                cur.execute('SELECT * FROM Triggers')
                return [r[0] for r in cur.fetchall()]

        def get_last_trigger_for_pull_request(self, pr_id):
            """
            Get the last commit for the provided pull request for which a build has been triggered
            :param pr_id: pull request id
            :return: last commit
            """

            with self.con:
                cur = self.con.cursor()
                cur.execute('SELECT CommitId FROM Triggers WHERE PullRequestId=?', (pr_id,))
                result = cur.fetchone()
                return result[0] if result else None

        def forget_pull_request(self, pr_id):
            """
            Stop tracking the specified pull request
            :param pr_id: pull request id
            """

            with self.con:
                cur = self.con.cursor()
                cur.execute('DELETE FROM Triggers WHERE PullRequestId=?', (pr_id,))

        def set_trigger_for_pull_request(self, pr_id, commit):
            """
            Record a triggered build for the specified pull request and commit
            :param pr_id: pull request id
            :param commit: commit id
            """

            with self.con:
                cur = self.con.cursor()
                cur.execute('REPLACE INTO Triggers VALUES(?, ?)', (pr_id, commit))

    def __init__(self):

        self.automation_configuration = AutomationConfiguration.get_static_instance()
        self.bitbucket_utils = BitbucketUtils(self.automation_configuration.project)
        self.bamboo_utils = BambooUtils(self.automation_configuration.project)
        self.state = PullRequestTriggerJob.PRTriggerState()
        self.target_build_plans = self.get_target_build_plans()

    def get_build_plan_key(self, source_branch, target_branch):
        """
        Retrieve the key of the plan that needs to be built based on the pull request's source and destination branches
        This method needs to be overridden in derived classes.
        """

        raise NotImplementedError('Cannot call method {0} of abstract class {1} instance'
                                  .format(inspect.currentframe().f_code.co_name, self.__class__.__name__))

    def get_target_build_plans(self):
        """
        Retrieve the build plans which are targets for triggering. It reads a mapping between branches of release and
        associated build plans. File is kept external in a source control.
        This method needs to be overridden in derived classes.
        """

        raise NotImplementedError('Cannot call method {0} of abstract class {1} instance'
                                  .format(inspect.currentframe().f_code.co_name, self.__class__.__name__))

    def trigger_build(self, pr):
        """
        Trigger the appropriate build plan based on the specified pull request
        Use the source and destination branches to determine the bamboo plan branch that needs to be triggered
        """

        # noinspection PyBroadException
        try:
            source_branch = pr['fromRef']['displayId']
            target_branch = pr['toRef']['displayId']
            # Subclasses provide the bamboo plan key
            plan_key = self.get_build_plan_key(source_branch, target_branch)
            # Trigger build
            # TODO
            self.bamboo_utils.bamboo_trigger_build_plan(plan_key)
        except Exception:
            return False
        else:
            return True

    def run(self):
        """Check all existing pull requests and trigger build plans as necessary."""

        # Retrieve all current open pull requests
        current_pull_requests = self.bitbucket_utils.bitbucket_get_all_pull_requests(
            self.automation_configuration.repo, 'OUTGOING', 'OPEN')

        print('The following branch mapping has been read: {0}'.format(self.target_build_plans))

        # Trigger builds for all pull requests which have been updated with new commits since last triggered
        for pr in current_pull_requests:
            pr_id = pr['id']
            pr_title = pr['title']
            pr_latest_commit = pr['fromRef']['latestCommit']
            last_triggered_commit = self.state.get_last_trigger_for_pull_request(pr_id)
            if pr_latest_commit != last_triggered_commit:
                print(
                    'Found new/updated commit in pull-request {0} ({1}) [commit: {2}]'.format(
                        pr_id, pr_title, pr_latest_commit)
                )
                if self.trigger_build(pr):
                    # Remember successful triggered builds
                    self.state.set_trigger_for_pull_request(pr_id, pr_latest_commit)
                else:
                    print('    ...FAILED')

        # Remove known pull requests which are no longer current
        current_pull_request_ids = [pr['id'] for pr in current_pull_requests]
        known_pull_request_ids = self.state.get_known_pull_requests()
        for pr_id in set(known_pull_request_ids).difference(current_pull_request_ids):
            self.state.forget_pull_request(pr_id)


class BambooPlanSettings(object):
    """
    Saves a specific bamboo branch configuration settings
    """
    def __init__(self, plan, plan_branch, build_args=None, bamboo_build_args=None,
                 bamboo_url=AtlassianUtils.BAMBOO_URL):
        """
        Configures a specific plan configuration
        :param plan: plan which needs to be triggered
        :param plan_branch: configured branch name
        :param build_args: string containing custom variables for the build (i.e. custom revision)
        :param bamboo_build_args: Dictionary containing the bamboo build variables
        :param bamboo_url: string containing URL to the bamboo server (i.e. 'https://bamboo1.sw.nxp.com/')
        """

        self.plan = plan
        self.plan_branch = plan_branch
        self.build_args = build_args
        self.bamboo_build_args = bamboo_build_args
        self.bamboo_url = bamboo_url
