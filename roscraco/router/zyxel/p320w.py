import re

from roscraco.router.base import RouterBase

from roscraco.helper import validator, converter, split_in_groups
from roscraco.exception import RouterFetchError, RouterParseError, \
     RouterSettingsError, RouterIdentityError, RouterLoginError

from roscraco.response import RouterInfo, TrafficStats, DMZSettings, \
     ConnectedClientsListItem, ConnectedClientsList, WirelessSettings, \
     DHCPReservationList, DHCPReservationListItem, DHCPServerSettings


class Zyxel_P320W(RouterBase):

    def __init__(self, *args, **kwargs):
        RouterBase.__init__(self, *args, **kwargs)
        self._is_logged_in = False

    def _handle_first_request(self):
        """We need to make an initial "login" request.

        This usually happens via an HTML form.
        If we don't login and try to access anything other than `/`,
        we'll be redirected to http://192.168.1.1/

        Login works on an IP basis. There's no sessions (cookies) or anything.
        After we've logged in our session is active for some time.
        """
        data = {'rc': '@', 'rd': 'login', 'TC': '', 'PS': self.password}
        contents = self._make_http_request_write('cgi-bin/logi', data)
        if 'Error : Password is incorrect!' in contents:
            raise RouterLoginError('Cannot login - wrong password.')
        self._is_logged_in = True

    def close(self):
        # It's a good idea to perform a logout, because no one else
        # will be able to log in until the current session expires
        # (the session is on an IP basis)
        try:
            if self._is_logged_in:
                # Only logout if we've made at least one successful request
                self._make_http_request_read('cgi-bin/logo?rc=@&rd=login')
                self._is_logged_in = False
        except RouterFetchError:
            pass

    def confirm_identity(self):
        c = self._make_http_request_read('')
        # Both of these strings are valid P-320W routers
        # <TITLE>.:: Welcome to ZyXEL P-320W (P-320W) ::. </TITLE>
        # <TITLE>.:: Welcome to ZyXEL P-320W (router) ::. </TITLE>
        if '<TITLE>.:: Welcome to ZyXEL P-320W' not in c:
            raise RouterIdentityError('Cannot confirm identity')

    def get_router_info(self):
        return parse_router_info(self._make_http_request_read('fwup.htm'))

    def get_uptime(self):
        return parse_uptime(self._make_http_request_read('status.htm'))

    def get_pppoe_online_time(self):
        return None

    def get_traffic_stats(self):
        return parse_traffic_stats(self._make_http_request_read('slist.htm'))

    def get_mac_address(self):
        return parse_mac_address(self._make_http_request_read('prim.htm'))

    def get_dns_servers(self):
        return parse_dns_servers(self._make_http_request_read('status.htm'))

    def get_connected_clients_list(self):
        return parse_connected_clients_list(self._make_http_request_read('clist.htm'))

    def get_dmz_settings(self):
        settings = DMZSettings()
        settings.set_supported_status(False)
        settings.set_enabled_status(False)
        settings.set_ip('0.0.0.0')
        return settings

    def push_dmz_settings(self, settings):
        return False

    def get_dhcp_settings(self):
        return parse_dhcp_settings(self._make_http_request_read('dhcp.htm'))

    def get_addr_reservation_list(self):
        return parse_addr_reservation_list(self._make_http_request_read('sdhcp.htm'))

    def push_addr_reservation_list(self, lst_new):
        lst_new.ensure_valid()

        lst_old = self.get_addr_reservation_list()
        if lst_old == lst_new:
            return True

        data = generate_addr_reservation_data(lst_new)
        self._make_http_request_write('cgi-bin/dhcp', data)
        return self.get_addr_reservation_list() == lst_new

    def get_wireless_settings(self):
        main = self._make_http_request_read('main.htm')
        security_type, link = generate_wireless_settings_link(main)
        html = self._make_http_request_read(link)
        return parse_wireless_setting(security_type, html)

    def push_wireless_settings(self, settings):
        data = generate_wireless_data(settings)

        # When updating WPA settings the router tries to generate some KEY
        # or whatever, which slows things down (~15 seconds).
        # For non-WPA update requests, we leave the default timeout
        timeout = 20.0 if settings.security_type_is_wpa else None
        self._make_http_request_write('cgi-bin/wlap', data, timeout=timeout)
        return self.get_wireless_settings() == settings

    @property
    def supports_reboot(self):
        return True

    def reboot(self):
        url = 'cgi-bin/rebo?D=&rd=space'
        self._make_http_request_write(url)


def parse_router_info(html):
    obj = RouterInfo()
    obj.set_hardware_version('P320W')

    regex_firmware = re.compile('fwug\[4\]\+" (.+?) "\+fwug\[5\]', re.DOTALL)
    match_object = regex_firmware.search(html)
    if match_object is None:
        raise RouterParseError('Cannot parse firmware version')
    obj.set_firmware_version(match_object.group(1))

    return obj


def parse_uptime(html):
    regex = re.compile('sta\[22\]\+" : ","([0-9]+):([0-9]+):([0-9]+)",')
    match_object = regex.search(html)
    if match_object is None:
        raise RouterParseError('Cannot parse uptime')
    hours, minutes, seconds = map(int, match_object.groups())
    return hours * 3600 + minutes * 60 + seconds


def parse_traffic_stats(html):
    regex = re.compile('slist\[0\]\+"</B>","([0-9]+)","([0-9]+)",')
    match_object = regex.search(html)
    if match_object is None:
        raise RouterParseError('Cannot parse traffic stats')
    packets_recv, packets_sent = map(int, match_object.groups())
    return TrafficStats(0, 0, packets_recv, packets_sent)


def parse_mac_address(html):
    regex = re.compile('NAME=_En VALUE="(.+?)"')
    match_object = regex.search(html)
    if match_object is None:
        raise RouterParseError('Cannot parse mac address')
    return converter.normalize_mac(match_object.group(1))


def parse_dns_servers(html):
    regex = re.compile('sta\[11\]\+" : ","(.+?)"')
    match_object = regex.search(html)
    if match_object is None:
        raise RouterParseError('Cannot parse dns servers')
    dns_ips = match_object.group(1).split(', ')
    return [ip for ip in dns_ips if validator.is_valid_ip_address(ip)]


def parse_connected_clients_list(html):
    lst = ConnectedClientsList()

    regex = re.compile('var x=new Array\((.+?)\);')
    match_object = regex.search(html)
    if match_object is None:
        raise RouterParseError('Cannot parse connected clients list')
    match_str = match_object.group(1)
    if match_str == '""':
        return lst

    import ast
    try:
        list_literal = '[%s]' % match_str
        list_items = ast.literal_eval(list_literal)
        list_items.pop() # empty 'sentinel' string - not needed
        list_items = [v.decode('utf-8', 'ignore') if isinstance(v, bytes) else v
                      for v in list_items]
        for ip, name, mac in split_in_groups(list_items, 3):
            item = ConnectedClientsListItem()
            item.set_client_name(name)
            item.set_mac(converter.normalize_mac(mac))
            item.set_ip(ip)
            item.set_lease_time(item.__class__.LEASE_TIME_PERMANENT)
            lst.append(item)
        return lst
    except Exception:
        return lst


def parse_dhcp_settings(html):
    is_enabled = '<INPUT TYPE=CHECKBOX NAME=_HE CHECKED>' in html

    # 192.168.1 is hardcoded.. only the last part changes
    regex = re.compile('<INPUT NAME=HR0 VALUE="([0-9]+)" SIZE=3 MAXLENGTH=3>')
    match_object = regex.search(html)
    if match_object is None:
        raise RouterParseError('Cannot parse dhcp start ip!')
    ip_last_part = match_object.group(1)
    ip_start = '192.168.1.%s' % ip_last_part

    # get the pool size to determine what the last IP is
    regex = re.compile('document.forms\[0\]\._HR1\.value=([0-9]+)-([0-9]+)')
    match_object = regex.search(html)
    if match_object is None:
        raise RouterParseError('Cannot parse dhcp pool size!')
    num1, num2 = map(int, match_object.groups())
    pool_size = num1 - num2
    ip_start_long = converter.ip2long(ip_start)
    ip_end_long = ip_start_long + pool_size
    ip_end = converter.long2ip(ip_end_long)

    settings = DHCPServerSettings()
    settings.set_enabled_status(is_enabled)
    settings.set_ip_start(ip_start)
    settings.set_ip_end(ip_end)
    settings.ensure_valid()
    return settings


def parse_addr_reservation_list(html):
    """
    Entries look like this:
        {status?}, {mac}, {ip_last_part}, {optional description}
        "1","00-11-11-11-11-11","52","",
        "1","00-11-11-11-11-11","52","R_user-cc5c756950",

    The status in front (0 or 1) is not important.
    It's 0 for all entries, when the list is empty,
    and 1 when there's at least one real entry.

    The IP prefix is always 192.168.1.

    The optional description only appears in entries
    not added manually, but automatically via a 'Reserve' checkbox in
    the connected clients list
    """
    regex = re.compile('^"0|1","(.+?)","([0-9]+)","(?:.*?)",\n')
    reservation_list = DHCPReservationList()
    reservation_list.set_reboot_requirement_status(False)
    for mac, ip_last_part in regex.findall(html):
        if ip_last_part == '0':
            continue
        ip = '192.168.1.%s' % ip_last_part
        item = DHCPReservationListItem()
        item.set_mac(converter.normalize_mac(mac))
        item.set_ip(ip)
        item.set_enabled_status(True)
        reservation_list.append(item)
    return reservation_list


def _resolve_wireless_security_type(cskm):
    """The ``cskm`` variable seen on every page,
    specifies the type of wireless security in use now.

    Depending on that variable, a unique wireless settings
    link is generated.
    """

    # cskm_value => (web link value, security_type)
    cskm_map = {}

    cskm_map['0'] = ('0000', WirelessSettings.SECURITY_TYPE_NONE)

    # WEP could either be WEP64 or WEP128..
    # there's no way we can determine that from this context..
    cskm_map['1'] = ('1000', 'wep')

    #Dynamic WEP (radius) - not supported
    cskm_map['1CHECKED'] = ('2000', WirelessSettings.SECURITY_TYPE_NONE)

    # WPA radius - not supported
    cskm_map['2CHECKED'] = ('8000', WirelessSettings.SECURITY_TYPE_NONE)
    cskm_map['3CHECKED'] = ('8000', WirelessSettings.SECURITY_TYPE_NONE)

    # WPA-PSK
    cskm_map['2'] = ('4000', WirelessSettings.SECURITY_TYPE_WPA)
    cskm_map['3'] = ('4000', WirelessSettings.SECURITY_TYPE_WPA)

    # No security, but there's also a Pre-Shared key on the page
    # Anyways, this is not supported
    cskm_map['4'] = ('0100', WirelessSettings.SECURITY_TYPE_NONE)
    cskm_map['5'] = ('0100', WirelessSettings.SECURITY_TYPE_NONE)

    # No security, but there's some radius settings on the page
    # Anyways, this is not supported
    cskm_map['4CHECKED'] = ('0200', WirelessSettings.SECURITY_TYPE_NONE)
    cskm_map['5CHECKED'] = ('0200', WirelessSettings.SECURITY_TYPE_NONE)

    return cskm_map.get(cskm, cskm_map.get('0'))


def generate_wireless_settings_link(html):
    """The link with the wireless settings is generated
    dynamically depending on 2 variables find on every page.
    These are the ``es0`` and ``cskm`` variables.
    What ``es0`` controls is not yet known, but ``cskm``
    represents the type of wireless security that's setup now.
    """
    regex = re.compile('es0="([0-9]+)";(?:.+?)cskm="(.+?)";', re.DOTALL)
    match_object = regex.search(html)
    if match_object is None:
        raise RouterParseError('Cannot parse wireless link variables!')
    es0, cskm = match_object.groups()
    link_value, security_type = _resolve_wireless_security_type(cskm)
    from time import time
    return security_type, 'wlan.htm?rc=&rf=%s&_=&_=&_=&_=&_=%s&_=&ZT=%d' % (
        link_value,
        es0,
        time()
    )


def parse_wireless_setting(security_type, html):
    obj = WirelessSettings()
    obj.add_security_support(WirelessSettings.SECURITY_TYPE_WEP64)
    obj.add_security_support(WirelessSettings.SECURITY_TYPE_WEP128)
    obj.add_security_support(WirelessSettings.SECURITY_TYPE_WPA)
    obj.set_auto_channel_support(False)
    obj.set_reboot_requirement_status(False)

    regex = re.compile('if \(""==""\) document\.forms\[0\]\.ZN\.value='
                       'unescape\("(.+?)"\);')
    match_object = regex.search(html)
    if match_object is None:
        raise RouterParseError('Cannot parse ssid!')
    ssid = match_object.group(1)
    obj.set_ssid(ssid)

    # security_type is either a valid value or 'wep',
    # in which case we've got to resolve it to WEP64 or WEP128
    if security_type == 'wep':
        regex = re.compile('(?:.+?)<OPTION CHECKED>(?:.+?)dw\(wlan\[25\]\)'
                           '(?:.+?)</SCRIPT>', re.DOTALL)
        if regex.search(html) is not None:
            security_type = WirelessSettings.SECURITY_TYPE_WEP64
        else:
            security_type = WirelessSettings.SECURITY_TYPE_WEP128

        regex = re.compile('<INPUT NAME=ZO0 VALUE="(.+?)" SIZE=26')
        match_object = regex.search(html)
        if match_object is None:
            raise RouterParseError('Cannot parse WEP password!')
        obj.set_password(match_object.group(1))
    elif security_type == WirelessSettings.SECURITY_TYPE_WPA:
        regex = re.compile('document\.forms\[0\]\.PK\.value=unescape\("(.+?)"\);')
        match_object = regex.search(html)
        if match_object is None:
            raise RouterParseError('Cannot parse WPA password!')
        obj.set_password(match_object.group(1))
    else: # No security
        obj.set_password('')
    obj.set_security_type(security_type)

    regex = re.compile('if\(i==([0-9]+)\)\nsel="SELECTED"')
    match_object = regex.search(html)
    if match_object is None:
        raise RouterParseError('Cannot parse channel!')
    obj.set_channel(int(match_object.group(1)))

    # `_esv` is either 0 or 1 and controls SSID broadcasting
    if '_esv=1' in html:
        obj.set_ssid_broadcast_status(False)

    regex = re.compile('wdv0=\("(.+?)"=="(.+?)"\)\?true:false')
    match_object = regex.search(html)
    if match_object is None:
        raise RouterParseError('Cannot parse enabled status!')
    val1, val2 = match_object.groups()
    obj.set_enabled_status(val1 == val2)

    return obj


def _denormalize_mac(mac):
    """Takes a normalized mac address (all lowercase hex, no separators)
    and converts it to the Zyxel format.

    Example::
        _denormalize_mac('abcdef123456') == 'ab-cd-ef-12-34-56'
    """
    return '-'.join((mac[i] + mac[i+1] for i in range(0, 12, 2)))


def generate_addr_reservation_data(lst):
    """The POST data we need to send contains the
    information about all reservation list items.
    """
    slots = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H']
    if len(slots) < len(lst):
        raise RouterSettingsError('More entries than slots!')

    data = {}
    data['Eb'] = 0
    data['rc'] = '@'
    data['rd'] = 'sdhcp'

    # Set some default data for all fields
    for slot_id in slots:
        data['DE' + slot_id] = 'o'
        data['DN' + slot_id] = ''
        data['Di' + slot_id] = 0 # last part of IP
        data['Dm' + slot_id] = '00-00-00-00-00-00' # MAC address

    for i, item in enumerate(lst):
        slot_id = slots[i]
        data['Di' + slot_id] = item.ip.split('.').pop()
        data['Dm' + slot_id] = _denormalize_mac(item.mac)

    return data


def generate_wireless_data(settings):
    """This is very ugly due to the fact that this incredibly
    stupid router expects the fields to come in order.

    If we change the order of them, the settings get corrupted,
    or rejected.

    This means that a dictionary cannot be used here,
    because its order is not guaranteed.
    Some fields (such as KM5) also need to be sent twice,
    which can't be done with a dictionary.
    """
    settings.ensure_valid()
    if settings.security_type_is_wep:
        CS = '1'
        rf = '1000'
    elif settings.security_type_is_wpa:
        CS = '2'
        rf = '4000'
    else:
        CS = '0'
        rf = '0000'

    if not settings.is_enabled:
        rf = ''

    data = []
    data.append(('RC', '@'))
    data.append(('rf', rf))
    data.append(('Xf', '1'))
    data.append(('prev', ''))

    data.append(('_ZN', ''))
    data.append(('_ZC', ''))
    data.append(('_ESS', ''))
    data.append(('_WD', ''))
    data.append(('CS', CS))

    if settings.is_enabled:
        data.append(('WD', 'o'))
        data.append(('xWD', 'on'))
    else:
        data.append(('WD', 'x'))

    data.append(('ZN', settings.ssid))

    data.append(('es', 'FFFC'))

    if not settings.is_broadcasting_ssid:
        data.append(('ES0', 'o'))
        data.append(('ES1', 'o'))
        data.append(('_ES', 'on'))

    data.append(('ZC', settings.channel))
    data.append(('_Security', ''))

    if settings.security_type_is_wep:
        data.append(('KM#3', '000F'))
        data.append(('KM0', 'x'))
        data.append(('ZP', ''))
        if settings.security_type == settings.__class__.SECURITY_TYPE_WEP64:
            zs = 0
            _ZS = '64-bit WEP'
        else:
            zs = 1
            _ZS = '128-bit WEP'
        if settings.is_wep_password_in_hex:
            ZS = zs + 1
        else:
            ZS = 128 + zs + 1
        data.append(('ZS', ZS))
        data.append(('_ZS', _ZS))
        # Authentication method = Both
        data.append(('AU', '2'))
        # related to ASCII/HEX radio buttons
        data.append(('_MZS', 'on'))
        # which WEP key to use
        data.append(('ZW', '0'))
        data.append(('ZO0', settings.password))
        data.append(('ZO1', ''))
        data.append(('ZO2', ''))
        data.append(('ZO3', ''))
    elif settings.security_type_is_wpa:
        data.append(('KM#3', '00FF'))
        data.append(('KM4', 'o'))
        data.append(('KM5', ''))
        data.append(('PK', settings.password))

    data.append(('KM5', ''))
    data.append(('rd', 'wlan'))

    return data
