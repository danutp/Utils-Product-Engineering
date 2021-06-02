import json
import os
import requests
import urlparse

from collections import namedtuple
from functools import wraps
from interface.atlassian import AtlassianAccount
from helper.utils import Utils


__copyright__ = "Copyright 2019-2021 NXP"


class HttpStatusCodes:
    """Class used for storing HTTP status codes"""

    # Status codes
    SUCCESS_OK = 200
    SUCCESS_CREATED = 201
    SUCCESS_NO_CONTENT = 204

    FAIL_BAD_REQUEST = 400
    FAIL_UNAUTHORIZED = 401
    FAIL_FORBIDDEN = 403
    FAIL_NOT_FOUND = 404
    FAIL_CONFLICT = 409
    FAIL_UNSUPPORTED = 415

    def __init__(self):
        pass


class RESTUtils:
    """
    Provides an API for interaction with Atlassian RESTfull services using Python requests library
    """

    HEADERS = {
            "Connection": "Keep-Alive",
            "Content-Type": "application/json;charset=UTF-8",
            "Accept": "application/json, text/plain, */*",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US,en;q=0.9",
            "DNT": "1",
            "User-Agent": "Garbage browser: 5.6"
        }

    TIMEOUT = 30

    def __init__(self):
        pass

    @staticmethod
    def pack_response_to_client(func):
        """Pack the response to user.
        :param func: The function to be wrapped
        :return: A structure known by client, containing significant response related data
        """

        @wraps(func)
        def get_response(*args, **kwargs):
            """Get the response from the wrapped function, pack and serve it to client.
            :param args: The function positional arguments
            :param kwargs: The function keyword arguments
            :return: The packed response, a namedtuple object containing the response as bool, the status code,
                     the binary content as returned by the corresponding request object attribute and the url used
                     within the request
            """

            packed_response = namedtuple('packed_response', ['response', 'status_code', 'content', 'url'])

            response = func(*args, **kwargs)

            return packed_response(
                response=True if response.status_code == HttpStatusCodes.SUCCESS_OK else False,
                status_code=response.status_code,
                content=response.content,
                url=response.url
            )

        return get_response

    @staticmethod
    def download(url, auth=None, timeout=None, destination=None, error_on_fail=False):
        # type: (str, AtlassianAccount, int, str, bool) -> None
        """Downloads a resource using requests
        :param url: Request URL
        :param auth: Authentication object to be used
        :param destination: The destination file to be used
        :param error_on_fail: Flag which specifies whether exception should be raised if download fails
        :param timeout: The timeout in seconds
        """

        destination = destination or os.path.join(os.getcwd(), urlparse.urlparse(url).path.split('/')[-1])

        response = RESTUtils.get(url, auth=auth, timeout=timeout)
        if response.status_code != HttpStatusCodes.SUCCESS_OK:
            if error_on_fail:
                raise Exception('Failed to fetch the requested resource: {0}'.format(url))
            print('WARNING: Failed to fetch the requested resource: {0}'.format(url))

        mode = 'w' if Utils.is_text(response.content) else 'wb'

        try:
            with open(destination, mode) as fd_out:
                fd_out.write(response.content)
            print('Successfully downloaded resource from {0} into {1}'.format(url, destination))
        except Exception as exc:
            print('Failed to write the destination file {0}: {1}'.format(destination, exc))

    @staticmethod
    def make_request(url, request_method, headers=None, auth=None, payload=None, timeout=None, allow_redirects=False,
                     **kwargs):
        # type: (str, str, str, AtlassianAccount, str, int, bool, dict) -> requests.request
        """Creates the request and return the response, using requests
        :param url: Request URL
        :param request_method: GET/POST/PUT
        :param headers: The headers to be used in request
        :param auth: The authentication object to be used
        :param payload: Extra details which are included into request body
        :param timeout: The timeout to be used in request
        :param allow_redirects: Specify whether the redirects will be allowed
        :param kwargs: Additional arguments to be passed to request
        """

        if kwargs:
            allowed_extra_params = ['proxies', 'verify', 'stream', 'cert']
            unknown_arguments_found = filter(lambda arg: arg not in allowed_extra_params, kwargs.keys())
            if unknown_arguments_found:
                raise ValueError(
                    'Unknown argument(s) found in request: {0}'.format(' '.join(unknown_arguments_found))
                )

        try:
            response = requests.request(
                request_method,
                url=url,
                headers=headers or RESTUtils.HEADERS,
                auth=requests.auth.HTTPBasicAuth(auth.username, auth.password)
                if (bool(auth.username) and bool(auth.password)) else None,
                data=json.dumps(payload) if payload else None,
                timeout=timeout or RESTUtils.TIMEOUT,
                allow_redirects=allow_redirects,
                **kwargs
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

        return response

    @staticmethod
    def get(url, headers=None, auth=None, timeout=None, **kwargs):
        # type: (str, str, AtlassianAccount, int, dict) -> RESTUtils.make_request
        """
        Run a GET REST call
        :param url: REST URI
        :param headers: The headers to be used in request
        :param auth: The authentication object to be used
        :param timeout: The timeout to be used when waiting fot server response
        :param kwargs: Additional arguments to be passed to request
        :return: REST call response object
        """

        return RESTUtils.make_request(url, 'GET', headers=headers, auth=auth, timeout=timeout, **kwargs)

    @staticmethod
    def post(url, headers=None, auth=None, payload=None, timeout=None, **kwargs):
        # type: (str, str, AtlassianAccount, str, int, dict) -> RESTUtils.make_request
        """
        Run a POST REST call
        :param url: REST URI
        :param headers: The headers to be used in request
        :param auth: The authentication object to be used
        :param payload: POST call payload
        :param timeout: The timeout to be used when waiting fot server response
        :param kwargs: Additional arguments to be passed to request
        :return: REST call response object
        """

        return RESTUtils.make_request(url, 'POST', headers=headers, auth=auth, payload=payload, timeout=timeout,
                                      **kwargs)

    @staticmethod
    def put(url, headers=None, auth=None, payload=None, timeout=None, **kwargs):
        # type: (str, str, AtlassianAccount, str, int, dict) -> RESTUtils.make_request
        """
        Run a PUT REST call
        :param url: REST URI
        :param headers: The headers to be used in request
        :param auth: The authentication object to be used
        :param payload: POST call payload
        :param timeout: The timeout to be used when waiting fot server response
        :param kwargs: Additional arguments to be passed to request
        :return: REST call response object
        """

        return RESTUtils.make_request(url, 'PUT', headers=headers, auth=auth, payload=payload, timeout=timeout,
                                      **kwargs)

    @staticmethod
    def delete(url, headers=None, auth=None, payload=None, timeout=None, **kwargs):
        # type: (str, str, AtlassianAccount, str, int, dict) -> RESTUtils.make_request
        """
        Run a POST REST call
        :param url: REST URI
        :param headers: The headers to be used in request
        :param auth: The authentication object to be used
        :param payload: POST call payload
        :param timeout: The timeout to be used when waiting fot server response
        :param kwargs: Additional arguments to be passed to request
        :return: REST call response object
        """

        return RESTUtils.make_request(url, 'DELETE', headers=headers, auth=auth, payload=payload, timeout=timeout,
                                      **kwargs)
