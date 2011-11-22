import base64
import re

from roscraco.router.base import RouterBase
from roscraco.helper import validator, converter, split_in_groups
from roscraco.exception import RouterParseError, RouterIdentityError

from roscraco.response import RouterInfo, TrafficStats, DMZSettings, \
     ConnectedClientsListItem, ConnectedClientsList, WirelessSettings, \
     DHCPReservationList, DHCPReservationListItem, DHCPServerSettings


class Tenda_W268R(RouterBase):

    def _perform_http_request(self, *args, **kwargs):
        auth = base64.b64encode('%s:%s' % (self.username, self.password))
        kwargs['headers'] = [
            ('Authorization', 'Basic %s' % auth),
        ]
        return RouterBase._perform_http_request(self, *args, **kwargs)

    def confirm_identity(self):
        uri = '%stop.html' % self.url_base
        _, headers, contents = self._perform_http_request(uri)

        header_server = headers.getheader('Server')
        if header_server != 'GoAhead-Webs':
            raise RouterIdentityError('Invalid Server header: %s' % header_server)

        if 'tenda_logo.jpg' not in contents:
            raise RouterIdentityError('Cannot confirm that this is a Tenda device.')

    def get_router_info(self):
        html = self._make_http_request_read('system_status.asp')
        return _parse_router_info(html)

    def get_uptime(self):
        html = self._make_http_request_read('system_status.asp')
        return _parse_uptime(html)

    def get_pppoe_online_time(self):
        html = self._make_http_request_read('system_status.asp')
        return _parse_pppoe_online_time(html)

    def get_traffic_stats(self):
        # This router doesn't report traffic statistics
        return TrafficStats(0, 0, 0, 0)

    def get_mac_address(self):
        html = self._make_http_request_read('system_status.asp')
        return _parse_mac_address(html)

    def get_dns_servers(self):
        html = self._make_http_request_read('system_status.asp')
        return _parse_dns_servers(html)

    def get_connected_clients_list(self):
        html = self._make_http_request_read('lan_dhcp_clients.asp')
        return _parse_connected_clients_list(html)

    def get_dmz_settings(self):
        html = self._make_http_request_read('nat_dmz.asp')
        return _parse_dmz_settings(html)

    def push_dmz_settings(self, settings):
        post_params = _generate_dmz_data(settings)
        contents = self._make_http_request_write('goform/VirSerDMZ', post_params)
        return _parse_dmz_settings(contents) == settings

    def get_dhcp_settings(self):
        html = self._make_http_request_read('lan_dhcps.asp')
        return _parse_dhcp_settings(html)

    def get_addr_reservation_list(self):
        html = self._make_http_request_read('lan_dhcp_clients.asp')
        return _parse_addr_reservation_list(html)

    def push_addr_reservation_list(self, lst_new):
        post_params = _generate_addr_reservation_data(lst_new)
        contents = self._make_http_request_write('goform/DhcpListClient', post_params)
        return _parse_addr_reservation_list(contents) == lst_new

    def get_wireless_settings(self):
        basic = self._make_http_request_read('wireless_basic.asp')
        security_settings = self._make_http_request_read('goform/wirelessGetSecurity')
        security = self._make_http_request_read('wireless_security.asp')
        return _parse_wireless_settings(basic, security, security_settings)

    def push_wireless_settings(self, settings):
        settings_old = self.get_wireless_settings()

        post_params = _generate_wireless_data_basic(settings)
        basic = self._make_http_request_write('goform/wirelessBasic', post_params)

        post_params = _generate_wireless_data_security(settings)
        security = self._make_http_request_write('goform/APSecurity', post_params)

        # Let's validate that all changes were saved as requested..

        if settings_old.is_enabled and not settings.is_enabled:
            # Going from enabled to disabled prevents some of the basic
            # settings from being fully commited.
            # Let's skip validation in that case and hope for the best.
            return True

        security_settings = self._make_http_request_read('goform/wirelessGetSecurity')
        settings_new = _parse_wireless_settings(basic, security, security_settings)
        return settings_new == settings

    @property
    def supports_reboot(self):
        return True

    def reboot(self):
        self._make_http_request_write('goform/SysToolReboot')


def _parse_router_info(html):
    obj = RouterInfo()

    match_obj = re.compile('hw_ver="(.+?)";').search(html)
    if match_obj is None:
        raise RouterParseError('Cannot determine hardware version')
    obj.set_hardware_version(match_obj.group(1))

    match_obj = re.compile('run_code_ver="(.+?)";').search(html)
    if match_obj is None:
        raise RouterParseError('Cannot determine firmware version')
    obj.set_firmware_version(match_obj.group(1))
    return obj


def _parse_uptime(html):
    match_obj = re.compile('uptime=\s"(.+?)";').search(html)
    if match_obj is None:
        raise RouterParseError('Cannot determine uptime')
    return int(match_obj.group(1))


def _parse_pppoe_online_time(html):
    match_obj = re.compile('conntime="(.+?)";').search(html)
    if match_obj is None:
        raise RouterParseError('Cannot determine connection time')
    return int(match_obj.group(1))


def _parse_mac_address(html):
    match_obj = re.compile('wan_mac="(.+?)";').search(html)
    if match_obj is None:
        raise RouterParseError('Cannot determine WAN mac address')
    return converter.normalize_mac(match_obj.group(1))


def _parse_dns_servers(html):
    dns_ips = re.compile('dns[12]="(.+?)";').findall(html)
    return [ip.strip(' ') for ip in dns_ips if validator.is_valid_ip_address(ip)]


def _parse_connected_clients_list(html):
    dhcp_list = re.compile('var dhcpList=new Array\((.*)\);').search(html)
    if dhcp_list is None:
        raise RouterParseError('Cannot find DHCP list.')
    dhcp_list = dhcp_list.group(1)

    results = re.compile("'(.+?);(.+?);(.+?);[01];(\d+)'").findall(dhcp_list)
    lst = ConnectedClientsList()
    for client_name, ip, mac, lease_time in results:
        if not validator.is_valid_ip_address(ip):
            raise RouterParseError('Invalid IP address: %s' % ip)
        if not validator.is_valid_mac_address(mac):
            raise RouterParseError('Invalid MAC address: %s' % mac)

        item = ConnectedClientsListItem()
        item.set_client_name(client_name)
        item.set_mac(converter.normalize_mac(mac))
        item.set_ip(ip)
        item.set_lease_time(int(lease_time))

        lst.append(item)

    return lst


def _parse_dmz_settings(html):
    settings = DMZSettings()
    settings.set_supported_status(True)
    settings.set_reboot_requirement_status(False)

    match_obj = re.compile('var\sdef_DMZIP\s=\s"(.*)";').search(html)
    if match_obj is None:
        raise RouterParseError('Cannot determine DMZ IP address')
    settings.set_ip(match_obj.group(1))

    match_obj = re.compile('var\sdef_dmzen\s=\s"(.+?)";').search(html)
    if match_obj is None:
        raise RouterParseError('Cannot determine DMZ enabled status')
    settings.set_enabled_status(match_obj.group(1) == '1')
    return settings


def _parse_dhcp_settings(html):
    settings = DHCPServerSettings()

    match_obj = re.compile('document.LANDhcpsSet.DHEN.checked = (0|1);').search(html)
    if match_obj is None:
        raise RouterParseError('Cannot determine DHCP enabled status')
    settings.set_enabled_status(match_obj.group(1) == '1')

    match_obj = re.compile('document.LANDhcpsSet.dips.value = \(\("(.+?)"').search(html)
    if match_obj is None:
        raise RouterParseError('Cannot determine DHCP start IP address')
    ip_start = match_obj.group(1)
    if not validator.is_valid_ip_address(ip_start):
        raise RouterParseError('IP start address is invalid: %s' % ip_start)
    settings.set_ip_start(ip_start)

    match_obj = re.compile('document.LANDhcpsSet.dipe.value = \(\("(.+?)"').search(html)
    if match_obj is None:
        raise RouterParseError('Cannot determine DHCP end IP address')
    ip_end = match_obj.group(1)
    if not validator.is_valid_ip_address(ip_end):
        raise RouterParseError('IP end address is invalid: %s' % ip_end)
    settings.set_ip_end(ip_end)

    return settings


def _parse_addr_reservation_list(html):
    reservations = re.compile('var StaticList = new Array\((.*)\);').search(html)
    if reservations is None:
        raise RouterParseError('Cannot find reservations list.')
    reservations_list = reservations.group(1)

    results = re.compile(';(.+?);(.+?);([12]);(\d+)').findall(reservations_list)
    reservation_list = DHCPReservationList()
    reservation_list.set_reboot_requirement_status(False)
    for ip, mac, mac_bind, _time in results:
        item = DHCPReservationListItem()
        item.set_mac(converter.normalize_mac(mac))
        item.set_ip(ip)
        item.set_enabled_status(mac_bind == '1')
        reservation_list.append(item)
    return reservation_list


def _parse_wireless_settings(basic, security, security_settings):
    settings = WirelessSettings()
    settings.add_security_support(WirelessSettings.SECURITY_TYPE_WEP64)
    settings.add_security_support(WirelessSettings.SECURITY_TYPE_WEP128)
    settings.add_security_support(WirelessSettings.SECURITY_TYPE_WPA)
    settings.add_security_support(WirelessSettings.SECURITY_TYPE_WPA2)
    # Changes take effect immediately without needing to reboot.
    settings.set_reboot_requirement_status(False)

    match_obj = re.compile('var enablewireless= "([01])";').search(basic)
    if match_obj is None:
        raise RouterParseError('Cannot determine wireless enabled status.')
    settings.set_enabled_status(match_obj.group(1) == '1')

    match_obj = re.compile('var channel_index  = "(\d+)";').search(basic)
    if match_obj is None:
        raise RouterParseError('Cannot determine wireless channel.')
    settings.set_channel(int(match_obj.group(1)))

    match_obj = re.compile('var broadcastssidEnable  = "([01])";').search(basic)
    if match_obj is None:
        raise RouterParseError('Cannot determine broadcast status.')
    # this is reversed, 0 means enable..
    settings.set_ssid_broadcast_status(match_obj.group(1) == '0')

    security_params = security_settings.strip().split('\r')
    settings.set_ssid(security_params[0])

    sec_type = security_params[2]
    if sec_type == 'WPA2PSK':
        security_type = WirelessSettings.SECURITY_TYPE_WPA2
        settings.set_password(security_params[13])
    elif sec_type == 'WPAPSK':
        security_type = WirelessSettings.SECURITY_TYPE_WPA
        settings.set_password(security_params[13])
    elif sec_type == 'WEPAUTO':
        # let's determine wep64 or wep128 by inspecting the first password
        wep_key_1 = security_params[6]
        if len(wep_key_1) in (5, 10):
            # 5 chars is for ASCII passwords, 10 is for HEX
            security_type = WirelessSettings.SECURITY_TYPE_WEP64
        else:
            security_type = WirelessSettings.SECURITY_TYPE_WEP128
        settings.set_password(wep_key_1)
    else:
        security_type = WirelessSettings.SECURITY_TYPE_NONE
    settings.set_security_type(security_type)

    return settings


def _generate_dmz_data(settings):
    settings.ensure_valid()
    post_params = {}
    post_params['GO'] = 'nat_dmz.asp'
    post_params['en'] = 1 if settings.is_enabled else 0
    post_params['dmzip'] = settings.ip
    return post_params


def _generate_addr_reservation_data(lst):
    lst.ensure_valid()

    def denormalize_mac(mac):
        # abcdef123456 => AB:CD:EF:12:34:45
        byte_octets = split_in_groups(mac, 2)
        return (':'.join(byte_octets)).upper()

    post_params = {}
    post_params['LISTLEN'] = len(lst)

    # a sequence of 1 or 0 flags, saying
    # whether the given item is enabled
    ip_mac_bind = ''

    for i, item in enumerate(lst):
        item_data = ';%s;%s;%d;86400' % (
            item.ip,
            denormalize_mac(item.mac),
            1 if item.is_enabled else 2,
        )
        post_params['list%d' % (i + 1)] = item_data
        ip_mac_bind += '1' if item.is_enabled else '0'

    post_params['IpMacEN'] = ip_mac_bind

    return post_params


def _generate_wireless_data_basic(settings):
    settings.ensure_valid()

    post_params = {}
    post_params['enablewirelessEx'] = 1 if settings.is_enabled else 0
    if settings.is_enabled:
        post_params['enablewireless'] = 1

    post_params['ssid'] = settings.ssid
    post_params['broadcastssid'] = int(settings.is_broadcasting_ssid)
    post_params['sz11gChannel'] = settings.channel

    # Below are some settings that we force on everyone,
    # because we don't handle them.
    post_params['bssid_num'] = 1 # hardcoded by default too, unknown purpose
    post_params['n_mode'] = 0 # Operating Mode (0: Mixed, 1: Green)
    post_params['wirelessmode'] = 9 # b/g/n
    post_params['n_bandwidth'] = 1 # Channel bandwidth (0: 20, 1: 20/40)
    post_params['n_gi'] = 1 # Guard interval = auto
    post_params['n_mcs'] = 33 # MCS = auto
    post_params['n_rdg'] = 1 # Reverse Direction Grant = enabled
    post_params['n_extcha'] = 0 # Extension channel
    post_params['n_amsdu'] = 0 # Aggregation MSDU = disabled

    return post_params


def _generate_wireless_data_security(settings):
    settings.ensure_valid()

    post_params = {}
    post_params['ssidIndex'] = 0 # unknown field purpose

    security_mode_map = {
        settings.SECURITY_TYPE_WPA2: 'WPA2PSK',
        settings.SECURITY_TYPE_WPA: 'WPAPSK',
        settings.SECURITY_TYPE_WEP64: 'WEPAUTO',
        settings.SECURITY_TYPE_WEP128: 'WEPAUTO',
        settings.SECURITY_TYPE_NONE: 'Disable',
    }
    security_mode = security_mode_map.get(settings.security_type, settings.SECURITY_TYPE_NONE)
    post_params['security_mode'] = security_mode
    post_params['security_shared_mode'] = 'WEP'

    post_params['wep_default_key'] = 1
    for i in range(1, 5):
        post_params['wep_key_%d' % i] = ''
        post_params['WEP%dSelect' % i] = 0

    if settings.security_type_is_wep:
        post_params['wep_key_1'] = settings.password
        post_params['WEP1Select'] = 0 if settings.is_wep_password_in_hex else 1
    elif settings.security_type_is_wpa:
        post_params['passphrase'] = settings.password
        post_params['keyRenewalInterval'] = 3600
        post_params['cipher'] = 1 # 1: AES, 0: TKIP, 2: AES & TKIP

    return post_params
