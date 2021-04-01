#!/usr/bin/python -tt
# -*- coding: utf-8 -*-


__copyright__ = "2019 NXP Semiconductors. All rights reserved."


import base64
import json
import os
import requests
import threading

from bs4 import BeautifulSoup
from debugging import MethodDebug
from interface.atlassian import BambooSettings


__debug_flag__ = BambooSettings().debug_mode or False


"""Bamboo API Module"""


class BambooAccount(object):
    def __init__(self):
        self.__username, self.__password = self.__load_credentials()

    @property
    def username(self):
        return self.__username

    @property
    def password(self):
        return self.__password

    @staticmethod
    def __load_credentials():
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               'bamboo',
                               'auth_credentials.json')) as fd:
            credentials = json.loads(fd.read())

        return credentials['username'], base64.b64decode(credentials['password'])


class BambooUtils(object):
    """Bamboo utils class."""

    REQUEST_DEFAULT_TIMEOUT = 30
    ARTIFACT_REQUEST_DEFAULT_TIMEOUT = 60

    def __init__(self):
        self.__account = BambooAccount()

        self.__trigger_plan_url_mask = r'https://{0}.sw.nxp.com/rest/api/latest/queue/'
        self.__stop_plan_url_mask = r'https://{0}.sw.nxp.com/build/admin/stopPlan.action'
        self.__plan_results_url_mask = r'https://{0}.sw.nxp.com/rest/api/latest/result/'
        self.__query_plan_url_mask = r'https://{0}.sw.nxp.com/rest/api/latest/plan/'
        self.__latest_queue_url_mask = r'https://{0}.sw.nxp.com/rest/api/latest/queue.json'
        self.__artifact_url_mask = r'https://{0}.sw.nxp.com/browse/{1}/artifact/{2}/{3}/'

        self.__server = None
        self.__stage = None
        self.__artifact = None
        self.__build_key = None
        self.__url_query_string = None
        self.__query_type = None

    @property
    def account(self):
        """Bamboo account."""

        return self.__account

    @property
    def trigger_plan_url_mask(self):
        """Trigger plan URL mask."""

        return self.__trigger_plan_url_mask

    @property
    def stop_plan_url_mask(self):
        """Stop plan URL mask."""

        return self.__stop_plan_url_mask

    @property
    def plan_results_url_mask(self):
        """Plan results URL mask."""

        return self.__plan_results_url_mask

    @property
    def query_plan_url_mask(self):
        """Query plan URL mask."""

        return self.__query_plan_url_mask

    @property
    def latest_queue_url_mask(self):
        """Latest queue URL mask."""

        return self.__latest_queue_url_mask

    @property
    def artifact_url_mask(self):
        """Artifact URL mask."""

        return self.__artifact_url_mask

    @property
    def headers(self):
        """Headers for a HTTP request."""

        return {
            "Connection": "Keep-Alive",
            "Content-Type": "application/json;charset=UTF-8",
            "Accept": "application/json, text/plain, */*",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US,en;q=0.9",
            "DNT": "1",
            "User-Agent": "Garbage browser: 5.6"
        }

    @property
    def server(self):
        """Bamboo server."""

        return self.__server

    @server.setter
    def server(self, server_value):
        """Bamboo server setter."""

        self.__server = server_value

    @property
    def build_key(self):
        """Build key."""

        return self.__build_key

    @build_key.setter
    def build_key(self, build_key_value):
        """Build key setter."""

        self.__build_key = build_key_value

    @property
    def stage(self):
        """Bamboo stage."""

        return self.__stage

    @stage.setter
    def stage(self, stage_value):
        """Bamboo stage setter."""

        self.__stage = stage_value

    @property
    def artifact(self):
        """Bamboo artifact."""

        return self.__artifact

    @artifact.setter
    def artifact(self, artifact_value):
        """Bamboo artifact setter."""

        self.__artifact = artifact_value

    @property
    def url_query_string(self):
        """URL query string."""

        return self.__url_query_string

    @url_query_string.setter
    def url_query_string(self, url_query_string_value):
        """URL query string setter."""

        self.__url_query_string = url_query_string_value

    @property
    def query_type(self):
        """Query type defined in BambooUtils. E.g plan_info/plan_status/..."""

        return self.__query_type

    @query_type.setter
    def query_type(self, query_type_value):
        """Query type setter."""

        self.__query_type = query_type_value

    @staticmethod
    def pack_response_to_client(values_to_pack=(None, None, None, None)):
        """Pack the response to user.
        :param values_to_pack: Values to pack in response dict
        :return: dictionary
        """

        # TODO response must be replaced with status
        return {
            'response': values_to_pack[0],
            'status_code': values_to_pack[1],
            'content': values_to_pack[2],
            'url': values_to_pack[3]
        }

    def is_plan_status_request(self):
        """Detects if we deal with a plan_status request."""

        return self.query_type == 'plan_status'

    def is_plan_info_request(self):
        """Detects if we deal with a plan_info request."""

        return self.query_type == 'plan_info'

    def is_stop_plan_request(self):
        """Detects if we deal with a stop_plan request."""

        return self.query_type == 'stop_plan'

    def is_query_queue_request(self):
        """Detects if we deal with a query_queue request."""

        return self.query_type == 'query_queue'

    def is_download_artifact_request(self):
        """Detects if we deal with a download_artifact request."""

        return self.query_type == 'download_artifact'

    def is_query_for_artifacts_request(self):
        """Detects if we deal with a query_for_artifacts request."""

        return self.query_type == 'query_for_artifacts'

    def is_artifact_related_request(self):
        """Detects if we deal with an artifact related request."""

        return self.is_download_artifact_request() or self.is_query_for_artifacts_request()

    @MethodDebug(debug=__debug_flag__)
    def create_url(self):
        """Creates the URL."""

        if not self.query_type:
            raise ValueError("No query type supplied!")

        if self.is_plan_status_request():
            return "{url}{build_key}.json?includeAllStates=true".format(
                url=self.query_plan_url_mask.format(self.server),
                build_key=self.build_key,
            )

        if self.is_plan_info_request():
            return "{url}{build_key}.json?max-results=10000".format(
                url=self.plan_results_url_mask.format(self.server),
                build_key=self.build_key,
            )

        if self.is_stop_plan_request():
            return "{url}?planResultKey={build_key}".format(
                url=self.stop_plan_url_mask.format(self.server),
                build_key=self.build_key
            )

        if self.is_query_queue_request():
            return "{url}?expand=queuedBuilds".format(
                url=self.latest_queue_url_mask.format(self.server),
            )

        elif self.is_artifact_related_request():
            return (
                "{url}{url_query_string}".format(
                    url=self.artifact_url_mask.format(
                        self.server, self.build_key, self.stage, self.artifact
                    ),
                    url_query_string=self.url_query_string)
            )

        raise ValueError("Query type not supported!")

    @MethodDebug(debug=__debug_flag__)
    def get_artifacts_from_html_page(self, page_content):
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

    @MethodDebug(debug=__debug_flag__)
    def process_response(self, response, url, destination_file=None):
        """Processes the response obtained after performing a request.
        :param response: Response object
        :param url: Request URL
        :param destination_file: File where artifact will be downloaded in case of such a request
        """

        # Check HTTP response code
        if response.status_code != 200:
            return self.pack_response_to_client(values_to_pack=(False, response.status_code, response.json(), url))

        artifacts = list()

        try:
            if self.is_query_for_artifacts_request():
                response = requests.get(url)
                artifacts = self.get_artifacts_from_html_page(response.content)

            elif self.is_download_artifact_request():
                response = requests.get(url)

                with open(destination_file, 'wb') as f:
                    f.write(response.content)

            else:
                # Get the JSON reply from the web page
                response.encoding = "utf-8"
                return self.pack_response_to_client(values_to_pack=(True, response.status_code, response.json(), url))

        except ValueError as error:
            raise ValueError("Error decoding JSON: {error}".format(error=error))
        except Exception as exception:
            raise Exception("Unknown exception: {exception}".format(exception=exception))

        # Send response to client
        response = self.pack_response_to_client(values_to_pack=(True, response.status_code, None, url))
        if self.is_query_for_artifacts_request():
            response['artifacts'] = artifacts

        return response

    @MethodDebug(debug=__debug_flag__)
    def make_request(self, url, request_method=None, request_payload=None, destination_file=None):
        """Creates the Bamboo request and process the response.
        :param url: Request URL
        :param request_method: GET/POST/...
        :param request_payload: Extra details which are included into request body
        :param destination_file: File where artifact will be downloaded in case of such a request
        """

        try:
            response = requests.request(
                request_method or 'GET',
                url=url,
                auth=requests.auth.HTTPBasicAuth(self.account.username,
                                                 self.account.password),
                headers=self.headers,
                data=json.dumps(request_payload) if request_payload else None,
                timeout=(
                    BambooUtils.ARTIFACT_REQUEST_DEFAULT_TIMEOUT
                    if self.query_type in ['download_artifact', 'query_for_artifacts']
                    else BambooUtils.REQUEST_DEFAULT_TIMEOUT
                ),
                allow_redirects=False
            )

        except requests.RequestException as exception:
            raise ValueError(
                "Exception when requesting URL: '{url}'{os_line_sep}{exception}".format(
                    url=url,
                    os_line_sep=os.linesep,
                    exception=exception
                )
            )

        except (requests.ConnectionError, requests.HTTPError) as error:
            raise ValueError(
                "Error when requesting URL: '{url}'{os_line_sep}{error}".format(
                    url=url,
                    os_line_sep=os.linesep,
                    error=error
                )
            )

        except (requests.ConnectTimeout, requests.Timeout) as timeout:
            raise ValueError(
                "Timeout when requesting URL: '{url}'{os_line_sep}{timeout}".format(
                    url=url,
                    os_line_sep=os.linesep,
                    timeout=timeout
                )
            )

        except Exception as exception:
            raise Exception(
                "Unknown exception when requesting URL: '{url}'{os_line_sep}{exception}".format(
                    url=url,
                    os_line_sep=os.linesep,
                    exception=exception
                )
            )

        return self.process_response(response, url, destination_file=destination_file)

    @MethodDebug(debug=__debug_flag__)
    def trigger_build(self, server=None, plan_key=None, req_values=None):
        """Method to trigger a build using Bamboo API

        :param server: Bamboo server used in API call (e.g.:<bamboo1/bamboo2>) [string]
        :param plan_key: Bamboo plan key [string]
        :param req_values: Values to insert into request (tuple)

        :return: A dictionary containing HTTP status_code and request content
        :raise: Exception, ValueError on Errors
        """

        if not all((server, plan_key)):
            return {'content': "Incorrect input provided!"}

        # Execute all stages by default if no options received
        request_payload = {'stage&executeAllStages': [True]}
        # req_values[0] = True/False
        if req_values:
            request_payload['stage&executeAllStages'] = [req_values[0]]

            # Example
            # req_value[1] = {'bamboo.driver': "xyz", bamboo.test': "xyz_1"}
            # API supports a list as values
            for key, value in req_values[1].iteritems():
                request_payload[key] = [value]

        url = "{url}{plan_key}.json".format(url=self.trigger_plan_url_mask.format(server), plan_key=plan_key)
        print("URL used to trigger build: '{url}'".format(url=url))

        return self.make_request(url, request_method='POST', request_payload=request_payload)

    @MethodDebug(debug=__debug_flag__)
    def query_build(self, server=None, build_key=None, query_type=None):
        """Method to query a plan build using Bamboo API.

        :param server: Bamboo server used in API call (e.g.:<bamboo1/bamboo2>) [string]
        :param build_key: Bamboo build key [string]
        :param query_type: Type of the query (e.g.: <plan_info/plan_status/stop_plan/query_results>) [string]

        :return: A dictionary containing HTTP status_code and request content
        :raise: Exception, ValueError on errors
        """

        if not all((server, build_key, query_type)):
            return {'content': "Incorrect input provided!"}

        self.server = server
        self.build_key = build_key
        self.query_type = query_type

        url = self.create_url()
        print("URL used in query: '{url}'".format(url=url))

        return self.make_request(url, request_method='GET')

    @MethodDebug(debug=__debug_flag__)
    def query_build_for_artifacts(self, server=None, build_key=None, query_type=None,
                                  stage=None, artifact=None, url_query_string=None):
        """Method to query Bamboo plan run for stage artifacts

        :param server: Bamboo server used in API call (e.g.:<bamboo1/bamboo2>) [string]
        :param build_key: Bamboo build key [string]
        :param query_type: Type of the query (e.g.: <plan_info/plan_status/stop_plan/download_artifact>) [string]
        :param stage: Bamboo plan stage name [string]
        :param artifact: Name of the artifact as in Bamboo plan stage job [string]
        :param url_query_string: Query string to compound the URL [string]

        :return: A dictionary containing HTTP status_code, request content and list of artifacts
        :raise: Exception, ValueError on Errors
        """

        if not all((server, build_key, query_type, stage, artifact)):
            return {'content': "Incorrect input provided!"}

        self.server = server
        self.build_key = build_key
        self.query_type = query_type
        self.stage = stage
        self.artifact = artifact
        self.url_query_string = url_query_string or ''

        url = self.create_url()
        print("URL used to query for artifacts: '{url}'".format(url=url))

        return self.make_request(url, request_method='GET', query_type=query_type)

    @MethodDebug(debug=__debug_flag__)
    def get_artifact(self, server=None, build_key=None, query_type=None,
                     stage=None, artifact=None, url_query_string=None, destination_file=None):
        """Method to download artifact from Bamboo plan

        :param server: Bamboo server used in API call (e.g.:<bamboo1/bamboo2>) [string]
        :param build_key: Bamboo build key [string]
        :param query_type: Type of the query (e.g.: <plan_info/plan_status/stop_plan/download_artifact>) [string]
        :param stage: Bamboo plan stage name [string]
        :param artifact: Name of the artifact as in Bamboo plan stage job [string]
        :param url_query_string: Query string to compound the URL [string]
        :param destination_file: Full path to destination file [string]

        :return: A dictionary containing HTTP status_code and request content
        :raise: Exception, ValueError on Errors
        """

        if not all((server, build_key, query_type, stage, artifact, destination_file)):
            return {'content': "Incorrect input provided!"}

        self.server = server
        self.build_key = build_key
        self.query_type = query_type
        self.stage = stage
        self.artifact = artifact
        self.url_query_string = url_query_string or ''

        url = self.create_url()
        print("URL used to download artifact: '{url}'".format(url=url))

        return self.make_request(url, request_method='GET', query_type=query_type, destination_file=destination_file)

    @MethodDebug(debug=__debug_flag__)
    def stop_build(self, server=None, build_key=None, query_type=None):
        """Method to stop a running plan from Bamboo using Bamboo API

        :param server: Bamboo server used in API call (e.g.:<bamboo1/bamboo2>) [string]
        :param build_key: Bamboo build key [string]
        :param query_type: Type of the query (e.g.: <plan_info/plan_status/stop_plan/query_results>) [string]

        :return: A dictionary containing HTTP status_code and request content
        :raise: Exception, ValueError on errors
        """

        if not all((server, build_key)):
            return {'content': "Incorrect input provided!"}

        self.server = server
        self.build_key = build_key
        self.query_type = query_type

        url = self.create_url()
        print("URL used to stop plan: '{url}'".format(url=url))

        return self.make_request(url, request_method='POST')

    @MethodDebug(debug=__debug_flag__)
    def kill_timeout_for_bamboo_build(self, kill_after_timeout=-1, server=None, build_key=None):
        """Method to watch an Job execution on Bamboo stage.
        If exceed the specified timeout, the method will stop the current plan

        :param server: Bamboo server used in API call (e.g.:<bamboo1/bamboo2>) [string]
        :param kill_after_timeout: Timeout interval to wait until stopping the plan (seconds) [integer]
        :param build_key: Bamboo build key [string]

        :return Thread
                None, no 'build_key/kill_after_timeout' supplied
        """

        if not build_key:
            print("\nNo build key supplied!\n")
            return None

        if not server:
            print("\nNo Bamboo server name supplied!\n")
            return None

        if kill_after_timeout == -1:
            print("\nAborting the execution of the method as 'kill_after_timeout = -1'!\n")
            return None

        kill_timeout = float(kill_after_timeout)

        print(
            "\nWatching the current Bamboo JOB under plan '{build_key}' "
            "for a timeout period of: '{timeout}' seconds\n".format(
                build_key=build_key, timeout=kill_timeout
            )
        )
        kill_timer = threading.Timer(kill_timeout, self.stop_build, [server, build_key, "stop_plan"])
        kill_timer.start()

        return kill_timer
