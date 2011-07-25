import urllib
import urllib2
import contextlib

from roscraco.exception import RouterFetchError


class RouterBase(object):
    """Base router controller class.

    All other controller classes inherit from this one,
    (hopefully) implementing all of its non-implemented methods.
    """

    def __init__(self, host, port, username, password):
        self._host = host
        self._port = int(port)
        self._username = username
        self._password = password

        self._requests_cache = {}
        self._is_first_request = True

    @property
    def host(self):
        return self._host

    @property
    def port(self):
        return self._port

    @property
    def username(self):
        return self._username

    @property
    def password(self):
        return self._password

    @property
    def url_base(self):
        """The base URL to which all requests would be relative to.

        Subclasses may wish to override this to make things
        more convenient.
        """
        return 'http://%s:%d/' % (self.host, self.port)

    def __not_implemented(self):
        raise NotImplementedError('Method needs to be implemented in a subclass.')

    def get_router_info(self):
        """Returns a :class:`roscraco.response.RouterInfo` object
        with system information about the router (hardware, firmware) version.
        """
        self.__not_implemented()

    def get_mac_address(self):
        """Returns the MAC address of the router in our so called
        generic format - lowercase HEX, no separators.
        """
        self.__not_implemented()

    def get_dns_servers(self):
        """Returns a list of IP addresses of the detected DNS servers."""
        self.__not_implemented()

    def get_pppoe_online_time(self):
        """Returns the time in seconds since the PPPoE connection
        was made.

        Returns None if such information is not available
        """
        self.__not_implemented()

    def get_uptime(self):
        """Returns the time in seconds since the router was last rebooted."""
        self.__not_implemented()

    def get_traffic_stats(self):
        """Returns a :class:`roscraco.response.TrafficStats` object
        with traffic statistics for the WAN interface.
        """
        self.__not_implemented()

    def get_connected_clients_list(self):
        """Returns a :class:`roscraco.response.ConnectedClientsList` object
        with information about clients that are current connected to the
        router, or have been connected to it recently.
        """
        self.__not_implemented()

    def get_dmz_settings(self):
        """Returns a :class:`roscraco.response.DMZSettings` object
        with DMZ settings information about the router.
        """
        self.__not_implemented()

    def push_dmz_settings(self, settings):
        """Updates the DMZ settings and returns True on success.

        :param settings: the DMZSettings object
        """
        self.__not_implemented()

    def get_dhcp_settings(self):
        """Returns a :class:`roscraco.response.DHCPServerSettings` object
        with information about the current status of the DHCP server
        (on/off, supported/non-supported, IP range, etc.).
        """
        self.__not_implemented()

    def get_addr_reservation_list(self):
        """Returns a :class:`roscraco.response.DHCPReservationList`
        with information about the current static entries in the DHCP
        reservation list.
        """
        self.__not_implemented()

    def push_addr_reservation_list(self, lst_new):
        """Updates the DHCP address reservation settings and returns True
        on success.

        :param lst_new: the DHCPReservationList object
        """
        self.__not_implemented()

    def get_wireless_settings(self):
        """Returns a :class:`roscraco.response.WirelessSettings` object
        with information about the current status of wireless connectivity
        for this router.
        """
        self.__not_implemented()

    def push_wireless_settings(self, settings):
        """Updates the wireless settings and returns True on success.

        :param settings: the WirelessSettings object
        """
        self.__not_implemented()

    @property
    def supports_reboot(self):
        """Tells whether the device can be rebooted from the web interface."""
        self.__not_implemented()

    def reboot(self):
        """Reboots the device."""
        self.__not_implemented()

    def confirm_identity(self):
        """Confirms that the router we're trying to access
        is of the expected type/model.

        If it's not it will throw an exception of type
        :class:`roscraco.exception.RouterIdentityError`.
        """
        self.__not_implemented()

    def invalidate_cache(self):
        """Clears any cached data that may have been gathered
        and starts clean.
        """
        self._invalidate_http_cache()

    def _invalidate_http_cache(self):
        """Clears the http requests cache."""
        self._requests_cache = {}

    def _make_http_request_read(self, path):
        """Makes an HTTP request to the given path.

        The path is prefixed with the base URL,
        obtained from :attr:`roscraco.router.RouterBase.url_base`.

        Read requests to the same URL are cached, until a write
        request comes along, which invalidates the cache.
        """
        url = self.url_base + path
        if url not in self._requests_cache:
            self._requests_cache[url] = self._perform_http_request(url)[2]
        return self._requests_cache[url]

    def _make_http_request_write(self, path, *args, **kwargs):
        """Makes a "write" HTTP request to the given path.

        ``Write`` here means that the request is potentially
        changing some data, so we're invalidating the http
        requests cache.

        Such requests sometimes use the POST request method,
        although not necessarily.
        """
        url = self.url_base + path
        self._invalidate_http_cache()
        return self._perform_http_request(url, *args, **kwargs)[2]

    def _handle_first_request(self):
        """To be implemented in a subclass
        (if it needs to do something special on the first request).
        """
        pass

    def _perform_http_request(self, url, data=None, headers=(), timeout=7.0):
        """Makes the actual HTTP request and returns the result.

        The result is a 3-tuple:
            - requested URL
            - info() - meta information, such as headers
            - contents
        """
        if self._is_first_request:
            self._is_first_request = False
            self._handle_first_request()

        if data is not None:
            if isinstance(data, dict) or isinstance(data, list):
                data = urllib.urlencode(data)
            else:
                raise RouterFetchError(
                    'POST data should be a dict, a list or None!'
                )

        try:
            req = urllib2.Request(url, data)
            for header, value in headers:
                req.add_header(header, value)
            with contextlib.closing(urllib2.urlopen(req, timeout=timeout)) as handle:
                self._is_logged_in = True
                return (
                    handle.geturl(),
                    handle.info(),
                    handle.read().decode('utf-8', 'ignore')
                )
        except Exception, e:
            raise RouterFetchError('Failed making request: %s' % repr(e))

    def close(self):
        """Performs cleanup, logout or whatever the device requires."""

    def __del__(self):
        try:
            self.close()
        except Exception:
            # close() may fail if __init__ didn't complete
            pass
