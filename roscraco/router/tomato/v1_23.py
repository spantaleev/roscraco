import re
import ast
import base64

from roscraco.router.base import RouterBase

from roscraco.helper import validator, converter
from roscraco.exception import RouterParseError, \
     RouterSettingsError, RouterIdentityError

from roscraco.response import RouterInfo, TrafficStats, DMZSettings, \
     ConnectedClientsListItem, ConnectedClientsList, WirelessSettings, \
     DHCPReservationList, DHCPReservationListItem, DHCPServerSettings


class Tomato_1_23(RouterBase):

    def _perform_http_request(self, *args, **kwargs):
        auth = base64.b64encode('%s:%s' % (self.username, self.password))
        kwargs['headers'] = [('Authorization', 'Basic %s' % auth)]
        return RouterBase._perform_http_request(self, *args, **kwargs)

    def confirm_identity(self):
        html = self._make_http_request_read('')
        if 'Tomato' not in html:
            raise RouterIdentityError(
                'Cannot confirm that this is a Tomato router!'
            )
        info = self.get_router_info()
        if info.firmware_version != 'Version 1.23':
            raise RouterIdentityError('Tomato router version mismatch!')

    def _get_http_id(self):
        """Extracts the session id (http id),
        which needs to be passed in some requests."""
        html = self._make_http_request_read('')
        return _parse_http_id(html)

    def _get_status_data_raw(self):
        http_id = self._get_http_id()
        status_uri = 'status-data.jsx?_http_id=%s' % http_id
        return self._make_http_request_read(status_uri)

    def get_router_info(self):
        html = self._make_http_request_read('')
        return _parse_router_info(html)

    def get_uptime(self):
        js = self._get_status_data_raw()
        return _parse_uptime(js)

    def get_pppoe_online_time(self):
        js = self._get_status_data_raw()
        return _parse_pppoe_online_time(js)

    def get_traffic_stats(self):
        html = self._make_http_request_read('bwm-monthly.asp')
        return _parse_traffic_stats(html)

    def get_mac_address(self):
        js = self._get_status_data_raw()
        return _parse_mac_address(js)

    def get_dns_servers(self):
        js = self._get_status_data_raw()
        return _parse_dns_servers(js)

    def get_connected_clients_list(self):
        html = self._make_http_request_read('status-devices.asp')
        return _parse_connected_clients_list(html)

    def get_dmz_settings(self):
        html = self._make_http_request_read('forward-dmz.asp')
        return _parse_dmz_settings(html)

    def push_dmz_settings(self, settings):
        http_id = self._get_http_id()
        data = _generate_dmz_data(http_id, settings)
        self._make_http_request_write('tomato.cgi', data)
        return self.get_dmz_settings() == settings

    def get_dhcp_settings(self):
        html = self._make_http_request_read('basic-network.asp')
        return _parse_dhcp_settings(html)

    def get_addr_reservation_list(self):
        html = self._make_http_request_read('basic-static.asp')
        return _parse_addr_reservation_list(html)

    def push_addr_reservation_list(self, lst_new):
        http_id = self._get_http_id()
        data = _generate_addr_reservation_data(http_id, lst_new)
        self._make_http_request_write('tomato.cgi', data)
        return self.get_addr_reservation_list() == lst_new

    def get_wireless_settings(self):
        html = self._make_http_request_read('basic-network.asp')
        return _parse_wireless_settings(html)

    def push_wireless_settings(self, settings):
        http_id = self._get_http_id()
        data = _generate_wireless_data(http_id, settings)
        self._make_http_request_write('tomato.cgi', data)
        return self.get_wireless_settings() == settings

    @property
    def supports_reboot(self):
        return True

    def reboot(self):
        http_id = self._get_http_id()
        data = {'_commit': 0, '_http_id': http_id, '_nvset': 0, '_reboot': 1}
        self._make_http_request_write('tomato.cgi', data)


def _parse_http_id(html):
    regex = "src='status-data.jsx\?_http_id=(TID(?:.+?))'>"
    match_object = re.compile(regex).search(html)
    if match_object is None:
        raise RouterParseError('Cannot determine http id!')
    return match_object.group(1)


def _parse_data_structure(inner_json):
    """Parses broken JSON that this router generates.

    Data structures look like this:
    {
        key: 'value',
        another_key: [1, 2, 3]
    }

    We're basically using what's between the main {},
    and are parsing that, returning a dictionary.
    """

    results = {}
    for line in inner_json.split('\n'):
        match_object = re.compile('^\s+(.+?):\s(.+?),?$').match(line)
        if match_object is None:
                continue
        key, value = match_object.groups()
        try:
            results[key] = ast.literal_eval(value)
        except ValueError:
            pass
    return results


def _parse_js_structure(js, name):
    """Extracts a javascript object by its name.

    Here's what it looks like initially:
    //
    object_name = {
        some stuff here
    };

    //

    We're parsing the broken JSON inside, and
    we're returning a dictionary.
    """

    regex = '//\n%s = \{(.+?)\};\n\n//' % name
    match_object = re.compile(regex, re.DOTALL).search(js)
    if match_object is None:
        raise RouterParseError('Cannot parse main structure data')
    return _parse_data_structure(match_object.group(1))


def _parse_router_info(html):
    regex = re.compile("<div class='version'>(.+?)</div>")
    match_object = regex.search(html)
    if match_object is None:
        raise RouterParseError('Cannot parse version')
    obj = RouterInfo()
    obj.set_hardware_version('Unknown')
    obj.set_firmware_version(match_object.group(1))
    return obj


def _parse_uptime(status_js):
    data = _parse_js_structure(status_js, 'sysinfo')
    try:
        return int(data['uptime'])
    except (KeyError, ValueError):
        raise RouterParseError('Cannot parse uptime!')


def _parse_pppoe_online_time(status_js):
    # Ensure that we're using PPPoE
    nvram = _parse_js_structure(status_js, 'nvram')
    try:
        if nvram['wan_proto'] != 'pppoe':
            return None
        regex = "stats.wanuptime = '(\d+) days?, (\d+):(\d+):(\d+)';"
        match_object = re.compile(regex).search(status_js)
        if match_object is None:
            return None
        days, hours, minutes, seconds = map(int, match_object.groups())
        return days * 86400 + hours * 3600 + minutes * 60 + seconds
    except (KeyError, ValueError):
        raise RouterParseError('Cannot parse pppoe online time!')


def _parse_traffic_stats(html):
    regex = 'monthly_history = \[\n(.+?)\];'
    match_object = re.compile(regex).search(html)
    if match_object is not None:
        try:
            array = ast.literal_eval('[%s]' % match_object.group(1))
            bytes_recv, bytes_sent = 0, 0
            for time_data, recv, sent in array:
                bytes_recv += recv
                bytes_sent += sent

            # The stats provided are in MB,
            # but we expect Bytes
            bytes_recv *= 1024
            bytes_sent *= 1024

            return TrafficStats(bytes_recv, bytes_sent, 0, 0)
        except (KeyError, ValueError):
            raise RouterParseError('Cannot parse traffic stats!')
    return TrafficStats(0, 0, 0, 0)


def _parse_mac_address(status_js):
    nvram = _parse_js_structure(status_js, 'nvram')
    try:
        return converter.normalize_mac(nvram['wan_hwaddr'])
    except KeyError:
        raise RouterParseError('Cannot parse MAC address!')


def _parse_dns_servers(status_js):
    regex = re.compile('//\ndns = \[(.+?)\];')
    match_object = regex.search(status_js)
    if match_object is None:
        return []
    try:
        ips = ast.literal_eval(match_object.group(1))
    except Exception:
        return []
    else:
        return [ip.strip(' ') for ip in ips if validator.is_valid_ip_address(ip)]


def _parse_connected_clients_list(html):
    lst = ConnectedClientsList()

    regex = re.compile('dhcpd_lease = \[ (.+?)\];\nlist = \[')
    match_object = regex.search(html)
    if match_object is None:
        return lst

    def parse_lease_time(lease):
        regex = '(\d+) days?, (\d+):(\d+):(\d+)'
        match_object = re.compile(regex).search(lease)
        if match_object is None:
            return ConnectedClientsListItem.__class__.LEASE_TIME_PERMANENT

        days, hours, minutes, seconds = map(int, match_object.groups())
        return days * 86400 + hours * 3600 + minutes * 60 + seconds

    try:
        array = ast.literal_eval('[%s]' % match_object.group(1))
        for name, ip, mac, lease_time in array:
            item = ConnectedClientsListItem()
            item.set_client_name(name)
            item.set_ip(ip)
            item.set_mac(converter.normalize_mac(mac))
            item.set_lease_time(parse_lease_time(lease_time))
            lst.append(item)
        return lst
    except ValueError:
        raise RouterParseError('Cannot parse connected clients!')


def _parse_dmz_settings(html):
    regex = "//\s+nvram = \{(.+?)\};\n\nvar lipp = '(.+?)';"
    match_object = re.compile(regex, re.DOTALL).search(html)
    if match_object is None:
        raise RouterParseError('Cannot parse DMZ settings')

    bad_json_settings, lipp = match_object.groups()
    nvram = _parse_data_structure(bad_json_settings)

    ip = nvram['dmz_ipaddr']
    if '.' not in ip:
        # it's the last part only.. it's shortened
        # and the rest is in lipp
        ip = lipp + ip

    obj = DMZSettings()
    obj.set_supported_status(True)
    obj.set_reboot_requirement_status(False)
    obj.set_enabled_status(nvram['dmz_enable'] == '1')
    obj.set_ip(ip)
    obj.ensure_valid()
    return obj


def _parse_dhcp_settings(html):
    regex = '//\s+nvram = \{(.+?)\};\n\nxob = '
    match_object = re.compile(regex, re.DOTALL).search(html)
    if match_object is None:
        raise RouterParseError('Cannot parse DHCP settings')

    array = _parse_data_structure(match_object.group(1))

    try:
        ip_start, ip_end = array['dhcpd_startip'], array['dhcpd_endip']
        is_enabled = array['lan_proto'] == 'dhcp'
    except KeyError:
        raise RouterParseError('Bad nvram for DHCP settings')

    if not validator.is_valid_ip_address(ip_start):
        raise RouterParseError('Invalid DHCP start IP: %s' % ip_start)

    if not validator.is_valid_ip_address(ip_end):
        raise RouterParseError('Invalid DHCP end IP: %s' % ip_end)

    obj = DHCPServerSettings()
    obj.set_enabled_status(is_enabled)
    obj.set_ip_start(ip_start)
    obj.set_ip_end(ip_end)
    obj.ensure_valid()
    return obj


def _parse_addr_reservation_list(html):
    regex = '//\s+nvram = \{(.+?)\};\n\nif '
    match_object = re.compile(regex, re.DOTALL).search(html)
    if match_object is None:
        raise RouterParseError('Cannot parse reservation list')

    array = _parse_data_structure(match_object.group(1))
    try:
        lst = DHCPReservationList()
        lst.set_reboot_requirement_status(False)

        for part in array['dhcpd_static'].split('>'):
            if part == '':
                continue
            mac, ip, name = part.split('<')
            item = DHCPReservationListItem()
            item.set_mac(mac)
            item.set_ip(ip)
            lst.append(item)
    except (KeyError, ValueError):
        raise RouterParseError('Bad nvram for reservation list')

    return lst


def _parse_wireless_settings(html):
    regex = '//\s+nvram = \{(.+?)\};\n\nxob = '
    match_object = re.compile(regex, re.DOTALL).search(html)
    if match_object is None:
        raise RouterParseError('Cannot parse wireless settings')

    array = _parse_data_structure(match_object.group(1))

    try:
        settings = WirelessSettings()
        settings.add_security_support(WirelessSettings.SECURITY_TYPE_WEP64)
        settings.add_security_support(WirelessSettings.SECURITY_TYPE_WEP128)
        settings.add_security_support(WirelessSettings.SECURITY_TYPE_WPA)
        settings.add_security_support(WirelessSettings.SECURITY_TYPE_WPA2)

        settings.set_reboot_requirement_status(False)
        settings.set_auto_channel_support(False)
        settings.set_ascii_wep_password_support_status(False)

        # Let's preserve all the settings, so that it's
        # easier to generate the data later
        settings.set_internal_param('nvram', array)

        sec_type = array['security_mode2']
        settings.set_security_type(WirelessSettings.SECURITY_TYPE_NONE)
        settings.set_password('')
        if sec_type == 'wep':
            if array['wl_wep_bit'] == '64':
                settings.set_security_type(WirelessSettings.SECURITY_TYPE_WEP64)
            else:
                settings.set_security_type(WirelessSettings.SECURITY_TYPE_WEP128)
            settings.set_password(array['wl_key1'])
        elif sec_type == 'wpa_personal':
            settings.set_security_type(WirelessSettings.SECURITY_TYPE_WPA)
            settings.set_password(array['wl_wpa_psk'])
        elif sec_type == 'wpa2_personal':
            settings.set_security_type(WirelessSettings.SECURITY_TYPE_WPA2)
            settings.set_password(array['wl_wpa_psk'])

        settings.set_ssid(array['wl_ssid'])
        settings.set_channel(array['wl_channel'])
        settings.set_ssid_broadcast_status(array['wl_closed'] == '0')
        settings.set_enabled_status(array['wl_radio'] == '1')
        return settings
    except (KeyError, ValueError):
        raise RouterParseError('Bad nvram for wireless settings')


def _generate_addr_reservation_data(http_id, lst_new):
    lst_new.validate()

    items = []
    for i, item in enumerate(lst_new):
        name = 'Client%d' % i
        items.append('<'.join((item.mac, item.ip, name)))

    if len(items) == 0:
        items_string = ''
    else:
        items.append('')
        items_string = '>'.join(items)

    data = {}
    data['ajax'] = 1
    data['_nextpage'] = 'basic-static.asp'
    data['_service'] = 'dhcpd-restart'
    data['_http_id'] = http_id
    data['dhcpd_static'] = items_string
    return data


def _generate_dmz_data(http_id, settings):
    settings.ensure_valid()

    data = {}
    data['_ajax'] = 1
    data['_http_id'] = http_id
    data['dmz_sip'] = ''
    data['_nextpage'] = 'forward-dmz.asp'
    data['_service'] = 'firewall-restart'
    data['dmz_enable'] = 1 if settings.is_enabled else 0
    data['dmz_ipaddr'] = settings.ip
    return data


def _generate_wireless_data(http_id, settings):
    settings.ensure_valid()

    nvram = settings.get_internal_param('nvram')
    if nvram is None:
        raise RouterSettingsError('Bad wireless settings. Missing nvram')

    # We'll use all the all settings (nvram)
    # as a base for the new stuff
    # Certain fields are 'status fields', so we
    # don't need to push them as settings
    #
    # Other fields are empty (like the WPA password field)
    # if we're using WEP, so pushing an empty WPA password field
    # would be invalid
    attrs_skip = (
        'dhcp_num', 'dhcp_start', 'lan_gateway',
        'wl_radius_port', 'wl0_hwaddr', 'http_id',
        'wan_ipaddr', 'pptp_server_ip', 'l2tp_server_ip',
        'wan_netmask', 'wan_gateway', 'ppp_idletime',
        'wl_radius_ipaddr', 'wl_radius_key',
        'wl_wpa_psk', 'wl_key1'
    )

    data = {}
    for k, v in nvram.items():
        if k not in attrs_skip:
            data[k] = v

    data['_http_id'] = http_id
    data['_ajax'] = 1
    data['_service'] = '*'
    data['_nextpage'] = 'basic-network.asp'
    data['_nextwait'] = 10
    data['wl_gmode'] = 1 # 0: B; 1: B+G; 2: B

    data['wl_radio'] = 1 if settings.is_enabled else 0
    data['wl_channel'] = settings.channel
    data['wl_ssid'] = settings.ssid
    data['wl_closed'] = 0 if settings.is_broadcasting_ssid else 1

    # `none` or `radius`
    data['wl_auth_mode'] = 'none'

    data['wl_wep'] = 'enabled' if settings.security_type_is_wep else 'disabled'

    # should be changed to 1 if we're changing the LAN IP
    data['_moveip'] = 0

    # value is good for security type None and WEP
    data['wl_akm'] = ''

    if settings.security_type_is_wpa:
        if settings.security_type == settings.__class__.SECURITY_TYPE_WPA:
            data['wl_akm'] = 'psk'
        else:
            data['wl_akm'] = 'psk2'


    data['security_mode'] = 'disabled'
    data['security_mode2'] = 'disabled'
    if settings.security_type_is_wep:
        data['security_mode'] = 'wep'
        data['security_mode2'] = 'wep'
        if settings.security_type == settings.__class__.SECURITY_TYPE_WEP64:
            data['wl_wep_bit'] = 64
        else:
            data['wl_wep_bit'] = 128
        data['wl_key'] = 1
        data['wl_key1'] = settings.password
    elif settings.security_type_is_wpa:
        data['wl_wpa_psk'] = settings.password
        data['wl_crypto'] = 'tkip+aes'
        if settings.security_type == settings.__class__.SECURITY_TYPE_WPA:
            data['security_mode'] = 'psk'
            data['security_mode2'] = 'wpa_personal'
        else:
            data['security_mode'] = 'psk2'
            data['security_mode2'] = 'wpa2_personal'

    return data
