from roscraco.helper import validator
from roscraco.exception import RouterSettingsError


class WirelessSettings(object):
    """Represents all available Wireless settings for a router."""

    SECURITY_TYPE_NONE = 'none'
    SECURITY_TYPE_WEP64 = 'wep64'
    SECURITY_TYPE_WEP128 = 'wep128'
    SECURITY_TYPE_WPA = 'wpa'
    SECURITY_TYPE_WPA2 = 'wpa2'

    #: List of properties to export using export()
    PROPERTIES = (
        'security_type', 'ssid', 'is_enabled', 'is_broadcasting_ssid',
        'channel', 'password'
    )

    def __init__(self):
        self._supports_wireless = True
        self._ssid = None
        self._enabled_status = True
        self._ssid_broadcast_status = True
        self._channel = None
        self._password = None
        self._internal_params = {}
        self._supported_security_types = set([self.__class__.SECURITY_TYPE_NONE])
        self._security_type = None
        self._supports_ascii_wep_passwords = True
        self._supports_auto_channel = True
        self._changes_require_reboot = True

    def set_auto_channel_support(self, value):
        self._supports_auto_channel = bool(value)

    @property
    def supports_auto_channel(self):
        """Tells whether auto channel is supported.

        Channel 0 is considered the auto channel, because that's
        how most routers represent the ``Auto`` value.

        Some devices, however, do not support Auto channel at all.
        """
        return self._supports_auto_channel

    def add_security_support(self, security_type):
        """Adds a new security type to the list of supported
        security types.
        """
        self._supported_security_types.add(security_type)

    @property
    def supported_security_types(self):
        return self._supported_security_types

    def set_security_type(self, security_type):
        self._security_type = security_type

    @property
    def security_type_is_wep(self):
        """Tells whether the current security type is WEP.

        Returns true for both WEP64 and WEP128.
        """
        return self._security_type in (self.__class__.SECURITY_TYPE_WEP64, self.__class__.SECURITY_TYPE_WEP128)

    @property
    def security_type_is_wpa(self):
        """Tells whether the current security type is WPA.

        Returns true for both WPA and WPA2.
        """
        return self._security_type in (self.__class__.SECURITY_TYPE_WPA, self.__class__.SECURITY_TYPE_WPA2)

    @property
    def security_type(self):
        return self._security_type

    def set_reboot_requirement_status(self, value):
        self._changes_require_reboot = bool(value)

    @property
    def changes_require_reboot(self):
        """Tells whether the router needs rebooting
        for changes to take effect.
        """
        return self._changes_require_reboot

    def set_support_status(self, value):
        self._supports_wireless = bool(value)

    @property
    def is_supported(self):
        """Tells whether the router supports wireless (most of them do)."""
        return self._supports_wireless

    def set_ssid(self, value):
        self._ssid = value

    @property
    def ssid(self):
        """The current SSID (wireless network name)."""
        return self._ssid

    def set_enabled_status(self, value):
        self._enabled_status = bool(value)

    @property
    def is_enabled(self):
        return self._enabled_status

    def set_ssid_broadcast_status(self, value):
        self._ssid_broadcast_status = bool(value)

    @property
    def is_broadcasting_ssid(self):
        """Tells whether the SSID status is being broadcasted publicly.

        If it is, than the network is publicly visible by anyone.
        """
        return self._ssid_broadcast_status

    def set_channel(self, value):
        self._channel = int(value)

    @property
    def channel(self):
        """The transmission channel for wireless communications."""
        return self._channel

    def set_password(self, value):
        self._password = value

    @property
    def password(self):
        """The current password for the given security type.

        The password is sometimes None for some routers, to indicate
        that the password cannot be determined.
        Some routers hide the current password from their web-interface,
        so we can't detect it (but that doesn't mean that we can't change it
        with a new one).
        """
        return self._password

    @property
    def is_wep_password_in_hex(self):
        """Tells whether the given WEP password is in HEX or in ASCII.

        Detecting this automatically allows us to set the ASCII/HEX
        field in the management interface automatically.
        """
        if not self.security_type_is_wep:
            raise RouterSettingsError('Not using WEP, but trying to validate password!')
        bit_length = 128 if self.security_type == self.__class__.SECURITY_TYPE_WEP128 else 64
        return validator.is_wep_password_in_hex(self.password, bit_length)

    def set_ascii_wep_password_support_status(self, value):
        self._supports_ascii_wep_passwords = bool(value)

    @property
    def supports_ascii_wep_passwords(self):
        """Tells whether the current router supports ASCII passwords
        for WEP security.

        Some devices only support HEX passwords.
        """
        return self._supports_ascii_wep_passwords

    def set_internal_param(self, key, value):
        self._internal_params[key] = value

    def get_internal_param(self, key):
        return self._internal_params[key] if key in self._internal_params else None

    def validate(self):
        errors = {}

        if not validator.is_valid_ssid(self.ssid):
            errors['ssid'] = 'Invalid SSID: %s' % self.ssid

        # most routers use channel 0 as the 'Auto' channel
        channel_min = 0 if self.supports_auto_channel else 1
        if not (channel_min <= self.channel <= 13):
            errors['channel'] = 'Invalid channel %d' % self.channel

        if self.security_type not in self._supported_security_types:
            errors['security_type'] = 'Invalid security type: %s' % self.security_type
        else:
            result = self.__validate_password()
            if result is not None:
                errors['password'] = result

        return errors

    def ensure_valid(self):
        errors = self.validate()
        if len(errors) != 0:
            raise RouterSettingsError(str(errors))

    def __validate_password(self):
        if self.security_type in (self.__class__.SECURITY_TYPE_WPA, self.__class__.SECURITY_TYPE_WPA2):
            if not validator.is_valid_wpa_psk_password(self.password):
                return 'Invalid WPA PSK password: %s' % self.password

        if self.security_type in (self.__class__.SECURITY_TYPE_WEP64, self.__class__.SECURITY_TYPE_WEP128):
            bit_length = 128 if self.security_type == self.__class__.SECURITY_TYPE_WEP128 else 64
            if not validator.is_valid_wep_password(self.password, bit_length):
                return 'Invalid WEP password for bit length %d: %s' % (bit_length, self.password)

            # Some devices only support HEX values for the WEP password field
            if not self.supports_ascii_wep_passwords and not self.is_wep_password_in_hex:
                return 'ASCII WEP passwords are not supported!'

        return None

    def eq(self, other, skip_attrs=()):
        # WEP passwords that use HEX are not case-sensitive, so we want
        # to validate them separately
        if self.security_type_is_wep and other.security_type_is_wep and \
           self.is_wep_password_in_hex and other.is_wep_password_in_hex:
            skip_attrs = skip_attrs + ('password',)
            try:
                if self.password.lower() != other.password.lower():
                    return False
            except AttributeError:
                return False

        # Don't try to compare passwords when there's no security type
        if self.security_type == self.__class__.SECURITY_TYPE_NONE and \
           other.security_type == self.__class__.SECURITY_TYPE_NONE:
               skip_attrs = skip_attrs + ('password',)

        for attr in self.__class__.PROPERTIES:
            if attr in skip_attrs:
                continue
            if getattr(self, attr, None) != getattr(other, attr, None):
                #print('[%s] %s != %s' % (
                #               attr,
                #               getattr(self, attr, None),
                #               getattr(other, attr, None)
                #))
                return False

        return True

    def __eq__(self, other):
        return self.eq(other)

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

