class TrafficStats(object):
    """Represents traffic statistics information for a given interface."""

    def __init__(self, bytes_recv, bytes_sent, packets_recv, packets_sent):
        self._bytes_recv = bytes_recv
        self._bytes_sent = bytes_sent
        self._packets_recv = packets_recv
        self._packets_sent = packets_sent

    @property
    def bytes_recv(self):
        return self._bytes_recv

    @property
    def bytes_sent(self):
        return self._bytes_sent

    @property
    def packets_recv(self):
        return self._packets_recv

    @property
    def packets_sent(self):
        return self._packets_sent

