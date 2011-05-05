import re
from ..exception import RouterError


WEP_CONSTRAINTS_MAP = {
    64: {'ascii': 5, 'hex': 10},
    128: {'ascii': 13, 'hex': 26},
    152: {'ascii': 16, 'hex': 32}
}


def is_valid_mac_address(mac):
    if is_valid_mac_address_normalized(mac):
        return True

    # The following regular expressions could probably
    # be merged into a single more complex one

    # separated by `-`
    regex = re.compile('(([a-fA-F0-9]{2}-){5})([a-fA-F0-9]{2})$')
    if regex.match(mac) is not None:
        return True

    # separated by `:`
    regex = re.compile('(([a-fA-F0-9]{2}:){5})([a-fA-F0-9]{2})$')
    if regex.match(mac) is not None:
        return True

    return False


def is_valid_mac_address_normalized(mac):
    """Validates that the given MAC address has
    what we call a normalized format.

    We've accepted the HEX only format (lowercase, no separators) to be generic.
    """
    return re.compile('^([a-f0-9]){12}$').match(mac) is not None


def is_valid_ip_address(ip):
    parts = ip.split('.')
    if len(parts) != 4:
        return False

    try:
        parts = map(int, parts)
    except ValueError:
        return False

    for part in parts:
        if part < 0 or part > 255:
            return False

    return True


def _is_hex_string(string):
    return re.compile('^([a-fA-F0-9]+)$').match(string) is not None


def is_valid_wpa_psk_password(password):
    try:
        password = password.decode('ascii')
    except (UnicodeDecodeError, UnicodeEncodeError):
        return False
    else:
        if password.strip(' ') != password:
            return False

        return 8 <= len(password) <= 63

def is_valid_wep_password(password, bit_length):
    """Validates a WEP password of the specified bit length,
    which imposes certain constraints on what's allowed."""


    # the password could be either HEX or ASCII
    # HEX is valid ASCII too
    try:
        password = password.decode('ascii')
    except (UnicodeDecodeError, UnicodeEncodeError):
        return False

    if password.strip(' ') != password:
        return False

    length = len(password)

    try:
        constraints = WEP_CONSTRAINTS_MAP[bit_length]

        if length == constraints['ascii']:
            # any ascii character works
            return True
        elif length == constraints['hex']:
            # if the string is that long, it can only be in HEX
            return _is_hex_string(password)

        return False
    except KeyError:
        raise RouterError('Invalid bit length: %d' % int(bit_length))


def is_wep_password_in_hex(password, bit_length):
    """Tells whether we're using HEX or ASCII for the specified password."""
    if password is None:
        return False
    # the password could be either HEX or ASCII
    # HEX is valid ASCII too
    try:
        password = password.decode('ascii')
    except (UnicodeDecodeError, UnicodeEncodeError):
        raise RouterError('Cannot validate password as HEX or ASCII: %s' %
                          password)

    length = len(password)

    try:
        constraints = WEP_CONSTRAINTS_MAP[bit_length]

        if length == constraints['ascii']:
            return False
        elif length == constraints['hex']:
            # if the string is that long, it can only be in HEX
            return _is_hex_string(password)

        return False
    except KeyError:
        raise RouterError('Invalid bit length: %d' % int(bit_length))


def is_valid_ssid(ssid):
    try:
        ssid = ssid.decode('ascii')
    except (UnicodeDecodeError, UnicodeEncodeError):
        return False
    else:
        if ssid.strip(' ') != ssid:
            return False
        return 2 <= len(ssid) <= 32


def is_ip_in_range(ip, ip_range_start, ip_range_end):
    """Tells whether the given IP (in string format) is inside the range."""

    from .converter import ip2long

    return ip2long(ip_range_start) <= ip2long(ip) <= ip2long(ip_range_end)
