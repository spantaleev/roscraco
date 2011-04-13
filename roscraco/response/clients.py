class ConnectedClientsList(list):
    """A response class representing the clients connected
    to the router at this time (or that have been recently connected).
    """
    pass


class ConnectedClientsListItem(object):
    """A client entry in the :class:`ConnectedClientsList`."""

    LEASE_TIME_PERMANENT = 'Permanent'

    def __init__(self):
        self._client_name = None
        self._mac_address = None
        self._ip_address = None
        self._lease_time = None

    def set_client_name(self, value):
        self._client_name = value

    @property
    def client_name(self):
        return self._client_name

    def set_mac(self, value):
        self._mac_address = value

    @property
    def mac(self):
        return self._mac_address

    def set_ip(self, value):
        self._ip_address = value

    @property
    def ip(self):
        return self._ip_address

    def set_lease_time(self, value):
        self._lease_time = value

    @property
    def lease_time(self):
        return self._lease_time

    @property
    def is_permanent_lease(self):
        return (self._lease_time == self.__class__.LEASE_TIME_PERMANENT)

    def __repr__(self):
        return '<%s: %s; %s>' % (self.__class__, self._client_name, self._ip_address)
