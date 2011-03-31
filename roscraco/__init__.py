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

__title__ = 'roscraco'
__version__ = '0.1.0'
__author__ = 'Slavi Pantaleev'
__license__ = 'BSD'
__copyright__ = 'Copyright 2011 Slavi Pantaleev'

ROUTER_TP_LINK = 'tplink'
ROUTER_CANYON = 'canyon'
ROUTER_NETGEAR = 'netgear'
ROUTER_TOMATO = 'tomato'
ROUTER_ZYXEL = 'zyxel'


def create_controller(router_type, model, *args, **kwargs):
    from exception import RouterNotSupported

    # type=tomato, model=1.23 => Tomato_1_23
    router_class_name = ''.join((
        router_type[0].upper(),
        router_type[1:],
        '_',
        model.replace('.', '_'),
    ))
    import_from = 'roscraco.router.%s' % router_type
    try:
        __import__(import_from)
    except ImportError:
        raise RouterNotSupported(
            '%s is not supported (no such module)' % router_type
        )

    import sys
    cls = getattr(sys.modules[import_from], router_class_name, None)
    if cls is None:
        raise RouterNotSupported(
            'Cannot find any class to instantiate for %s (%s) in %s' %
                (router_class_name, model, import_from)
        )

    return cls(*args, **kwargs)
