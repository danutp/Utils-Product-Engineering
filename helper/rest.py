import base64
import json
import os
import platform
import requests

current_python_version = platform.python_version_tuple()
if int(current_python_version[0]) >= 3:
    from urllib import request, error
else:  # Python 2.7
    import urllib2

# Constants
REQUEST_DEFAULT_TIMEOUT = 30
ARTIFACT_REQUEST_DEFAULT_TIMEOUT = 60

# Status codes
SUCCESS_OK = 200

# Temporary Switch
USE_REQUESTS_LIB = True


class AtlassianAccount(object):
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
                               'atlassian',
                               'auth_credentials.json')) as fd:
            credentials = json.loads(fd.read())

        return credentials['username'], base64.b64decode(credentials['password'])


class RESTServiceConfiguration(object):
    """
    Abstraction for a REST service configuration
    """

    def __init__(self, __auth_context):
        """
        :param __auth_context: a SSLContext instance used to authenticate to the REST service for performing REST calls
        """

        self.__auth_context = __auth_context

    def get_auth_context(self):
        """
        :return: the REST service authentication context
        """

        return self.__auth_context


class RESTUtilsPy2:
    """
    Provides an API for interaction with RESTfull services for Python 2.7
    """

    def __init__(self):

        pass

    @staticmethod
    def build_request(uri, user, password):
        """
        Builds a REST call request object
        :param uri: REST URI
        :param user: REST service user name
        :param password: REST service password
        :return: The request object
        """

        try:
            request_ = urllib2.Request(url=uri)
            request_.add_header('Content-Type', 'application/json')
            auth = base64.encodestring('{0}:{1}'.format(user, password)).replace('\n', '')
            request_.add_header('Authorization', 'Basic {0}'.format(auth))
            return request_
        except Exception as e:
            print('REST request build resulted in exception for the following URI: {0}'.format(uri))
            raise e

    @staticmethod
    def get(rest_service_configuration, uri, user, password):
        """
        Run a GET REST call
        :param rest_service_configuration: REST service configuration
        :param uri: REST URI
        :param user: REST server user name
        :param password: REST server password
        :return: REST call response object
        """

        try:
            return urllib2.urlopen(url=RESTUtilsPy2.build_request(uri, user, password),
                                   context=rest_service_configuration.get_auth_context())
        except Exception as e:
            print('REST GET resulted in exception upon calling the following URI: {0}'.format(uri))
            raise e

    @staticmethod
    def post(rest_service_configuration, uri, user, password, payload):
        """
        Run a POST REST call
        :param rest_service_configuration: REST service configuration
        :param uri: REST URI
        :param user: REST server user name
        :param password: REST server password
        :param payload: POST call payload
        :return: REST call response object
        """

        try:
            return urllib2.urlopen(url=RESTUtilsPy2.build_request(uri, user, password),
                                   data=json.dumps(payload),
                                   context=rest_service_configuration.get_auth_context())
        except urllib2.HTTPError as e:
            print('REST POST resulted in exception upon calling the following URI: {0}. '
                  'The exception raised is:\n{1}'.format(uri, e.read()))
            raise e
        except Exception as e:
            print('REST POST resulted in exception upon calling the following URI: {0}'.format(uri))
            raise e

    @staticmethod
    def put(rest_service_configuration, uri, user, password, payload):
        """
        Run a PUT REST call
        :param rest_service_configuration: REST service configuration
        :param uri: REST URI
        :param user: REST server user name
        :param password: REST server password
        :param payload: POST call payload
        :return: REST call response object
        """

        request_ = RESTUtilsPy2.build_request(uri, user, password)

        # urllib2 supports only GET and POST requests, so we override its get_method in order to be able
        # to send PUT requests
        try:
            request_.get_method = lambda: 'PUT'
            return urllib2.urlopen(url=request_,
                                   data=json.dumps(payload),
                                   context=rest_service_configuration.get_auth_context())
        except Exception as e:
            print('REST PUT resulted in exception upon calling the following URI: {0}'.format(uri))
            raise e


class RESTUtilsPy3:
    """
    Provides an API for interaction with RESTfull services for Python 3.x
    """

    def __init__(self):
        pass

    @staticmethod
    def build_request(uri, user, password):
        """
        Builds a REST call request object
        :param uri: REST URI
        :param user: REST service user name
        :param password: REST service password
        :return: The request object
        """

        try:
            request_ = request.Request(url=uri)
            auth = base64.b64encode('{0}:{1}'.format(user, password)).replace('\n', '')
            request_.add_header('Authorization', 'Basic {0}'.format(auth))
            return request_
        except Exception as e:
            print('REST request build resulted in exception for the following URI: {0}'.format(uri))
            raise e

    @staticmethod
    def get(rest_service_configuration, uri, user, password):
        """
        Run a GET REST call
        :param rest_service_configuration: REST service configuration
        :param uri: REST URI
        :param user: REST server user name
        :param password: REST server password
        :return: REST call response object
        """

        try:
            return request.urlopen(url=RESTUtilsPy3.build_request(uri, user, password),
                                   context=rest_service_configuration.get_auth_context())
        except Exception as e:
            print('REST GET resulted in exception upon calling the following URI: {0}'.format(uri))
            raise e

    @staticmethod
    def post(rest_service_configuration, uri, user, password, payload):
        """
        Run a POST REST call
        :param rest_service_configuration: REST service configuration
        :param uri: REST URI
        :param user: REST server user name
        :param password: REST server password
        :param payload: POST call payload
        :return: REST call response object
        """

        try:
            return request.urlopen(url=RESTUtilsPy3.build_request(uri, user, password),
                                   data=json.dumps(payload),
                                   context=rest_service_configuration.get_auth_context())
        except error.HTTPError as e:
            print('REST POST resulted in exception upon calling the following URI: {0}. '
                  'The exception raised is:\n{1}'.format(uri, e.read()))
            raise e
        except Exception as e:
            print('REST POST resulted in exception upon calling the following URI: {0}'.format(uri))
            raise e

    @staticmethod
    def put(rest_service_configuration, uri, user, password, payload):
        """
        Run a PUT REST call
        :param rest_service_configuration: REST service configuration
        :param uri: REST URI
        :param user: REST server user name
        :param password: REST server password
        :param payload: POST call payload
        :return: REST call response object
        """

        request_ = RESTUtilsPy3.build_request(uri, user, password)

        # urllib supports only GET and POST requests, so we override its get_method in order to be able
        # to send PUT requests
        try:
            request_.get_method = lambda: 'PUT'
            return request.urlopen(url=request_,
                                   data=json.dumps(payload),
                                   context=rest_service_configuration.get_auth_context())
        except Exception as e:
            print('REST PUT resulted in exception upon calling the following URI: {0}'.format(uri))
            raise e


class RESTUtilsRequests:
    """
    Provides an API for interaction with RESTfull services for Python using requests library
    """

    def __init__(self):
        self.__server = None
        self.__stage = None
        self.__artifact = None
        self.__build_key = None
        self.__url_query_string = None
        self.__query_type = None

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
    def build_key(self):
        """Build key."""

        return self.__build_key

    @build_key.setter
    def build_key(self, build_key_value):
        """Build key setter."""

        self.__build_key = build_key_value

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

    @property
    def build_key(self):
        """Build key."""

        return self.__build_key

    @build_key.setter
    def build_key(self, build_key_value):
        """Build key setter."""

        self.__build_key = build_key_value

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

    def create_url(self, server, build_key, query_type, stage, artifact, url_query_string):
        """Creates the URL."""

        self.server = server
        self.build_key = build_key
        self.query_type = query_type
        self.stage = stage
        self.artifact = artifact
        self.url_query_string = url_query_string or ''

        if not self.query_type:
            raise ValueError("No query type supplied!")

        if self.is_plan_status_request():
            return "{url}{build_key}.json?includeAllStates=true".format(
                url=AtlassianUtils.BAMBOO_QUERY_PLAN_URL.format(self.server),
                build_key=self.build_key,
            )

        if self.is_plan_info_request():
            return "{url}{build_key}.json?max-results=10000".format(
                url=AtlassianUtils.BAMBOO_PLAN_RESULTS_URL.format(self.server),
                build_key=self.build_key,
            )

        if self.is_stop_plan_request():
            return "{url}?planResultKey={build_key}".format(
                url=AtlassianUtils.BAMBOO_STOP_PLAN_URL.format(self.server),
                build_key=self.build_key
            )

        if self.is_query_queue_request():
            return "{url}?expand=queuedBuilds".format(
                url=AtlassianUtils.BAMBOO_LATEST_QUEUE_URL.format(self.server),
            )

        elif self.is_artifact_related_request():
            return (
                "{url}{url_query_string}".format(
                    url=AtlassianUtils.BAMBOO_ARTIFACT_URL.format(
                        self.server, self.build_key, self.stage, self.artifact
                    ),
                    url_query_string=self.url_query_string)
            )

        raise ValueError("Query type not supported!")

    def make_request(self, url, username, password, request_method, query_type, payload, destination_file):
        """Creates the Bamboo request and process the response, using requests
        :param url: Request URL
        :param username: username
        :param password: password
        :param request_method: GET/POST/...
        :param query_type: query_type
        :param payload: Extra details which are included into request body
        :param destination_file: File where artifact will be downloaded in case of such a request
        """

        query_type = query_type or self.query_type

        try:
            response = requests.request(
                request_method or 'GET',
                url=url,

                auth=requests.auth.HTTPBasicAuth(username,
                                                 password),
                headers=self.headers,
                data=json.dumps(payload) if payload else None,
                timeout=(
                    ARTIFACT_REQUEST_DEFAULT_TIMEOUT
                    if query_type in ['download_artifact', 'query_for_artifacts']
                    else REQUEST_DEFAULT_TIMEOUT
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

    def process_response(self, response, url, destination_file=None):
        """Processes the response obtained after performing a request.
        :param response: Response object
        :param url: Request URL
        :param destination_file: File where artifact will be downloaded in case of such a request
        """

        # Check HTTP response code
        if response.status_code != SUCCESS_OK:
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

    def get(self, rest_service_configuration, url, username, password, query_type, destination_file):
        """
        Run a GET REST call
        :param rest_service_configuration: kept for compatibility
        :param url: REST URI
        :param username: REST server user name
        :param password: REST server password
        :param query_type: query_type
        :param destination_file: File where artifact will be downloaded in case of such a request
        :return: REST call response object
        """

        rest_service_configuration = rest_service_configuration
        return self.make_request(url, username, password,
                                 request_method='GET',
                                 query_type=query_type,
                                 payload=None,
                                 destination_file=destination_file)

    def post(self, rest_service_configuration, url, username, password, query_type, payload):
        """
        Run a POST REST call
        :param rest_service_configuration: kept for compatibility
        :param url: REST URI
        :param username: REST server user name
        :param password: REST server password
        :param payload: POST call payload
        :param query_type: query_type
        :return: REST call response object
        """

        rest_service_configuration = rest_service_configuration
        return self.make_request(url, username, password,
                                 request_method='POST',
                                 query_type=query_type,
                                 payload=payload,
                                 destination_file=None)

    def put(self, rest_service_configuration, url, username, password, query_type, payload):
        """
        Run a PUT REST call
        :param rest_service_configuration: kept for compatibility
        :param url: REST URI
        :param username: REST server user name
        :param password: REST server password
        :param query_type: query_type
        :param payload: POST call payload
        :return: REST call response object
        """

        rest_service_configuration = rest_service_configuration
        request_ = self.make_request(url, username, password,
                                     request_method=None,
                                     query_type=query_type,
                                     payload=payload,
                                     destination_file=None)

        try:
            # TODO: TO BE TESTED
            request_.request_method = lambda: 'PUT'
            return self.make_request(request_, username, password,
                                     request_method=request_method,
                                     query_type=query_type,
                                     payload=payload,
                                     destination_file=None)
        except Exception as exception:
            raise exception


class RESTUtils:
    """
    Provides an API for interaction with RESTfull services
    """

    def __init__(self):
        pass


if not USE_REQUESTS_LIB:
    if int(current_python_version[0]) >= 3:
        RESTUtils = RESTUtilsPy3
    else:  # Python 2.7
        RESTUtils = RESTUtilsPy2
else:
    RESTUtils = RESTUtilsRequests
