# -*- coding: utf-8 -*

"""
    roscraco
    ~~~~~~~~

    A library for managing home routers (networking equipment).

    :copyright: (c) 2011 by Slavi Pantaleev.
    :license: BSD, see LICENSE.txt for more details.
"""

from . import helper
from . import response
from . import router
from exception import RouterNotSupported


__title__ = 'roscraco'
__version__ = '0.3.1'
__author__ = 'Slavi Pantaleev'
__license__ = 'BSD'
__copyright__ = 'Copyright 2011 Slavi Pantaleev'


ROUTER_TP_LINK = 'tplink'
ROUTER_CANYON = 'canyon'
ROUTER_NETGEAR = 'netgear'
ROUTER_TOMATO = 'tomato'
ROUTER_ZYXEL = 'zyxel'
ROUTER_TENDA = 'tenda'


def get_supported_types():
    """Returns a list of supported router types."""
    import sys
    this = sys.modules[__name__]
    return [getattr(this, k) for k in dir(this) if k.startswith('ROUTER_')]


def _get_type_module(router_type):
    """Returns the module that provides the implementation
    for this router type and throws an exception for invalid types."""
    module = getattr(router, router_type, None)
    if module is None:
        raise RouterNotSupported('%s is not a supported router type.' % router_type)
    return module


def _ucfirst(string):
    return string[0].upper() + string[1:]


def get_supported_models(router_type):
    """Returns a list of supported models for the given type
    and throws an exception for invalid types."""
    module = _get_type_module(router_type)
    # All model classes are prefixed this way..
    cls_prefix = _ucfirst(router_type) + '_'
    prefix_len = len(cls_prefix)
    return [k[prefix_len:] for k in dir(module) if k.startswith(cls_prefix)]


def create_controller(router_type, router_model, *args, **kwargs):
    module = _get_type_module(router_type)

    # type=tomato, model=1.23 => class_name=Tomato_1_23
    router_class_name = ''.join((
        _ucfirst(router_type),
        '_',
        router_model.replace('.', '_'),
    ))

    cls = getattr(module, router_class_name, None)
    if cls is None:
        raise RouterNotSupported(
            '%s is not a supported model for %s.' % (
                    router_model,
                    router_type,
                )
        )
    return cls(*args, **kwargs)
