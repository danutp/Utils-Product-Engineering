import base64
import json
import platform

current_python_version = platform.python_version_tuple()
if int(current_python_version[0]) >= 3:
    from urllib import request, error
else:  # Python 2.7
    import urllib2


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
            return urllib2.urlopen(url=RESTUtils.build_request(uri, user, password),
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
            return urllib2.urlopen(url=RESTUtils.build_request(uri, user, password),
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
        request_ = RESTUtils.build_request(uri, user, password)

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


class RESTUtils:
    """
    Provides an API for interaction with RESTfull services
    """

    def __init__(self):
        pass


if int(current_python_version[0]) >= 3:
    RESTUtils = RESTUtilsPy3
else: # Python 2.7
    RESTUtils = RESTUtilsPy2