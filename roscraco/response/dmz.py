from roscraco.helper import validator
from roscraco.exception import RouterSettingsError


class DMZSettings(object):
    """Represents the DMZ settings for a router."""

    #: List of properties to export using export()
    PROPERTIES = (
        'is_enabled', 'ip'
    )

    def __init__(self):
        self._is_supported = False
        self._is_enabled = False
        self._ip = None
        self._changes_require_reboot = True

    def set_reboot_requirement_status(self, value):
        self._changes_require_reboot = bool(value)

    @property
    def changes_require_reboot(self):
        """Tells whether the router needs rebooting
        for changes to take effect.
        """
        return self._changes_require_reboot

    @property
    def is_supported(self):
        """Tells whether the route supports DMZ."""
        return self._is_supported

    def set_supported_status(self, value):
        self._is_supported = bool(value)

    @property
    def is_enabled(self):
        """Tells whether the DMZ feature is enabled."""
        return self._is_enabled

    def set_enabled_status(self, value):
        self._is_enabled = bool(value)

    @property
    def ip(self):
        """The IP address of the DMZ host."""
        return self._ip

    def set_ip(self, value):
        self._ip = value

    def validate(self):
        errors = {}
        if not validator.is_valid_ip_address(self.ip):
            errors['ip'] = 'Invalid IP: %s' % self.ip
        return errors

    def ensure_valid(self):
        errors = self.validate()
        if len(errors) != 0:
            raise RouterSettingsError(str(errors))

    def __eq__(self, other):
        return self.ip == other.ip and self.is_enabled == other.is_enabled

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return id(self)

    def __repr__(self):
        mode = 'ENABLED' if self.is_enabled else 'DISABLED'
        return '<%s: %s/%s>' % (self.__class__, mode, self.ip)

    def export(self):
        """Exports the most important settings attributes,
        omitting any internal attributes.
        """
        export = {}
        for attr in self.__class__.PROPERTIES:
            export[attr] = getattr(self, attr, None)
        return export
