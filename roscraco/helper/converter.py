from ..exception import RouterParseError

def ip2long(ip_addr):
    """Converts an IP address string to an integer."""
    from socket import inet_aton
    from struct import unpack
    ip_packed = inet_aton(ip_addr)
    ip = unpack('!L', ip_packed)[0]
    return ip


def long2ip(ip):
    """Converts an integer representation of an IP address to string."""
    from socket import inet_ntoa
    from struct import pack
    return inet_ntoa(pack('!L', ip))


def normalize_mac(mac):
    """Converts any MAC address format to lowercase HEX with no separators."""
    from validator import is_valid_mac_address
    mac = mac.lower()
    if not is_valid_mac_address(mac):
        raise RouterParseError('MAC address %s is invalid!' % mac)
    return mac.replace(':', '').replace('-', '')
