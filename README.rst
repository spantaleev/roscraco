roscraco
========

roscraco (short for ROuter SCRAping and COntrol) is a library for
managing networking devices (routers).

The targeted (and currently supported) devices are home routers.

Settings are fetched and pushed from/to devices by using their
standard web-management interface (HTTP).

The type of device being managed is abstracted away and is
only important initially (when the controller object is created).
From the developer's standpoint, settings are then managed the same way
regardless of the device's type.


Installing
----------

roscraco is available on PyPI_ and can be installed using **pip** or **easy_install**::

    pip install roscraco

or::

    easy_install roscraco


Supported devices
-----------------

The library supports the following devices:

* TP-Link
    - WR340G (until v3)
    - WR340Gv4
    - WR740N
    - WR741N
    - WR940N
    - WR941N
* Netgear
    - WGR614v7
    - WGR614v8
    - WGR614v9
* Canyon
    - CNWF514
    - CNPWF514N1
    - CNPWF518N3
* Zyxel
    - P320W
    - P330W
* Tenda
    - W268R
* Tomato (routers using Tomato firmware)
    - version 1.23


Supported features
------------------

* Fetching router information (MAC address, uptime, DNS servers, traffic statistics, connected clients)
* Fetching DHCP server settings
* Fetching and updating DMZ settings
* Fetching and updating DHCP address reservation settings
* Fetching and updating Wireless connectivity settings
* Rebooting

Some of the (usually more advanced) options of a given settings object
cannot be controlled.
For most of these options a "sane" value (usually default) is picked
and will potentially overwrite any custom values that are currently set.


Usage example
-------------

Creating a controller instance::

    import roscraco
    controller = roscraco.create_controller(
        roscraco.ROUTER_TP_LINK, 'WR340G',
        'localhost', 8080, 'username', 'password'
    )

Print a lot of information about the device::

    roscraco.helper.print_info(controller)

Change some Wireless settings::

    # Fetch the current wireless settings
    settings = controller.get_wireless_settings()

    # Switch to the next transmission channel
    settings.set_channel(setings.channel + 1)

    # Disable password authentication
    settings.set_security_type(settings.SECURITY_TYPE_NONE)

    # Change the SSID (network name)
    settings.set_ssid('NewNetworkName')

    # Send the new wireless settings to the router
    controller.push_wireless_settings(settings)

Be nice and log out of the device properly
(you can also use ``contextlib.closing``)::

    controller.close()

.. _PyPI: http://pypi.python.org/pypi/roscraco
