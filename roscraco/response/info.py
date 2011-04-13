class RouterInfo(object):
    """Represents some system information about the router,
    such as hardware and firmware version.
    """

    def __init__(self):
        self._hardware_version = None
        self._firmware_version = None

    def set_hardware_version(self, value):
        self._hardware_version = value

    @property
    def hardware_version(self):
        return self._hardware_version

    def set_firmware_version(self, value):
        self._firmware_version = value

    @property
    def firmware_version(self):
        return self._firmware_version
