#!/usr/bin/python -tt
# -*- coding: utf-8 -*-

from pprint import pprint

__copyright__ = "Copyright 2021 NXP"


class FunctionDebug(object):
    """Debug a function.

    This decorator is used for debugging a function, with normal arguments, i.e, not printing out the data of the
    class it's contained in.

    Keyword arguments:
    debug -- Whether or not you want to debug the function.
    """
    def __init__(self, debug):
        self.__debug = debug

    def __call__(self, function):
        def wrapper(*args, **kwargs):
            if self.__debug:
                pprint(args)
                pprint(kwargs)

            return function(*args, **kwargs)

        return wrapper


class MethodDebug(object):
    """Debug a class method.

    This decorator is used for debugging a class method, with normal arguments, and self. When using this decorator,
    the method will print out it's arguments and the attributes of the class it's contained in.

    Keyword arguments:
    debug -- Whether or not you want to debug the method.
    """
    def __init__(self, debug):
        self.__debug = debug

    def __call__(self, function):
        def wrapper(function_self, *args, **kwargs):
            if self.__debug:
                pprint(function_self.__dict__)
                pprint(args)
                pprint(kwargs)

            return function(function_self, *args, **kwargs)

        return wrapper
