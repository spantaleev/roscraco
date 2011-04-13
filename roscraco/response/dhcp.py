from roscraco.helper import validator, converter
from roscraco.exception import RouterSettingsError


class DHCPReservationList(list):
    """A response class representing the router's
    address reservation list (static DHCP entries).
    """

    def __init__(self, *args, **kwargs):
        list.__init__(self, *args, **kwargs)
        self._supports_reservations = True
        self._changes_require_reboot = True
        self._internal_params = {}

    def set_reservation_support_status(self, value):
        self._supports_reservations = bool(value)

    @property
    def supports_reservations(self):
        """Tells whether address reservation is supported
        by the given device.
        """
        return self._supports_reservations

    def set_reboot_requirement_status(self, value):
        self._changes_require_reboot = bool(value)

    @property
    def changes_require_reboot(self):
        """Tells whether changing address reservation settings
        requires a device reboot for changes to take effect.
        """
        return self._changes_require_reboot

    def set_internal_param(self, key, value):
        """Sets some internal information to be 'carried' with this instance.

        This information may be needed when pushing new settings.
        """
        self._internal_params[key] = value

    def get_internal_param(self, k):
        """Retrieves the internal information
        set by :meth:`set_internal_param`.
        """
        return self._internal_params[k] if k in self._internal_params else None

    def has_ip(self, ip):
        """Tells whether the given IP address has an entry
        in the DHCP reservation list.
        """
        for item in self:
            if item.ip == ip:
                return True
        return False

    def has_ip_mac_entry(self, ip, mac):
        """Tells whether there's an entry that matches both
        the given IP and MAC address.
        """
        for item in self:
            if item.ip == ip and item.mac == mac:
                return True
        return False

    def validate(self):
        for item in self:
            errors = item.validate()
            if len(errors) != 0:
                return errors
        return {}

    def ensure_valid(self):
        for item in self:
            item.ensure_valid()

    def __eq__(self, other):
        if len(self) != len(other):
            return False

        for idx, item in enumerate(self):
            if item != other[idx]:
                return False
        return True

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return id(self)

    def export(self):
        """Exports the most important settings attributes,
        omitting any internal attributes.
        """
        export = {}
        for i, item in enumerate(self):
            export['entry_%d' % i] = item.export()
        return export


class DHCPReservationListItem(object):
    """Represents a single entry in the DHCP address reservation table."""

    #: Properties to export()
    PROPERTIES = (
        'mac', 'ip'
    )

    def __init__(self):
        self._mac_address = None
        self._ip_address = None
        self._is_enabled = True

    def set_mac(self, value):
        self._mac_address = converter.normalize_mac(value)

    @property
    def mac(self):
        return self._mac_address

    def set_ip(self, value):
        self._ip_address = value

    @property
    def ip(self):
        return self._ip_address

    def set_enabled_status(self, value):
        self._is_enabled = bool(value)

    @property
    def is_enabled(self):
        return self._is_enabled

    def validate(self):
        errors = {}
        if not validator.is_valid_ip_address(self.ip):
            errors['ip'] = 'Invalid IP address: %s' % self.ip
        if not validator.is_valid_mac_address_normalized(self.mac):
            errors['mac'] = 'Invalid normalized MAC address: %s' % self.mac
        return errors

    def ensure_valid(self):
        errors = self.validate()
        if len(errors) != 0:
            raise RouterSettingsError(str(errors))

    def __repr__(self):
        return '<%s: %s; %s>' % (self.__class__, self._ip_address, self._mac_address)

    def __eq__(self, other):
        for attr in ('ip', 'mac', 'is_enabled'):
            if getattr(self, attr, None) != getattr(other, attr, None):
                return False
        return True

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return id(self)

    def export(self):
        """Exports the most important settings attributes,
        omitting any internal attributes.
        """
        export = {}
        for attr in self.__class__.PROPERTIES:
            export[attr] = getattr(self, attr, None)
        return export


class DHCPServerSettings(object):
    """Represents the DHCP server settings.

    This is important, because it gives us information on the IP
    range in which addresses can be reserved
    (if DHCP is supported/enabled at all).
    """

    def __init__(self):
        self._ip_start = '192.168.1.100'
        self._ip_end = '192.168.1.199'
        self._is_enabled = True

    @property
    def ip_start(self):
        return self._ip_start

    def set_ip_start(self, value):
        self._ip_start = value

    @property
    def ip_end(self):
        return self._ip_end

    def set_ip_end(self, value):
        self._ip_end = value

    @property
    def is_enabled(self):
        return self._is_enabled

    def set_enabled_status(self, value):
        self._is_enabled = bool(value)

    def validate(self):
        errors = {}

        if not validator.is_valid_ip_address(self._ip_start):
            errors['ip_start'] = 'Invalid start IP: %s' % self._ip_start

        if not validator.is_valid_ip_address(self._ip_end):
            errors['ip_end'] = 'Invalid end IP: %s' % self._ip_end

        if converter.ip2long(self._ip_start) > converter.ip2long(self._ip_end):
            errors['ip_range'] = 'Invalid IP range: from %s to %s' % (self._ip_start, self._ip_end)

        return errors

    def ensure_valid(self):
        errors = self.validate()
        if len(errors) != 0:
            raise RouterSettingsError(str(errors))
