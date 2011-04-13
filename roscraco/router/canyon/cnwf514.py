import re
import base64

from roscraco.router.base import RouterBase

from roscraco.helper import validator, converter
from roscraco.exception import RouterParseError, RouterIdentityError

from roscraco.response import RouterInfo, TrafficStats, DMZSettings, \
     ConnectedClientsListItem, ConnectedClientsList, WirelessSettings, \
     DHCPReservationList, DHCPServerSettings


class Canyon_CNWF514(RouterBase):

    def _perform_http_request(self, *args, **kwargs):
        auth = base64.b64encode('%s:%s' % (self.username, self.password))
        kwargs['headers'] = [('Authorization', 'Basic %s' % auth)]
        return RouterBase._perform_http_request(self, *args, **kwargs)

    def confirm_identity(self):
        _, headers, contents = self._perform_http_request('%shome.asp' %
                                                          self.url_base)
        header_server = headers.getheader('Server')
        if header_server != 'GoAhead-Webs':
            raise RouterIdentityError('Invalid Server header: %s' % header_server)

        string_to_find = '<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->'
        if string_to_find not in contents:
            raise RouterIdentityError('Cannot find string in contents: %s' % string_to_find)

    def get_router_info(self):
        return _parse_router_info(self._make_http_request_read('status.asp'))

    def get_pppoe_online_time(self):
        return None  # online time not specified anywhere in the interface

    def get_uptime(self):
        return _parse_uptime_to_seconds(self._make_http_request_read('status.asp'))

    def get_traffic_stats(self):
        return _parse_traffic_stats(self._make_http_request_read('stats.asp'))

    def get_mac_address(self):
        return _parse_mac_address(self._make_http_request_read('status.asp'))

    def get_dns_servers(self):
        return _parse_dns_servers(self._make_http_request_read('tcpipwan.asp'))

    def get_connected_clients_list(self):
        return _parse_connected_clients_list(self._make_http_request_read('dhcptbl.asp'))

    def get_wireless_settings(self):
        html = [self._make_http_request_read(path) for path in ('wlbasic.asp', 'wladvanced.asp', 'wlwpa.asp', 'wlwep.asp')]
        return _parse_wireless_settings(*html)

    def push_wireless_settings(self, settings):
        data_basic = _generate_wireless_data_basic(settings)
        self._make_http_request_write('goform/formWlanSetup', data_basic)

        data_advanced = _generate_wireless_data_advanced(settings)
        self._make_http_request_write('goform/formAdvanceSetup', data_advanced)

        if settings.security_type_is_wep:
            data_wep = _generate_wireless_data_wep(settings)
            self._make_http_request_write('goform/formWep', data_wep)

        data_security = _generate_wireless_data_security(settings)
        self._make_http_request_write('goform/formWlEncrypt', data_security)

        return settings.eq(self.get_wireless_settings(), skip_attrs=('password',))

    def get_dmz_settings(self):
        # DMZ breaks remote management for this router..
        # so we're not enabling support for it at all
        settings = DMZSettings()
        settings.set_supported_status(False)
        settings.set_enabled_status(False)
        settings.set_ip('0.0.0.0')
        return settings

    def push_dmz_settings(self, settings):
        # DMZ is broken for this router,
        # refusing to do anything
        return False

    def get_addr_reservation_list(self):
        lst = DHCPReservationList()
        lst.set_reservation_support_status(False)
        lst.set_reboot_requirement_status(False)
        return lst

    def push_addr_reservation_list(self, lst):
        return False

    def get_dhcp_settings(self):
        return _parse_dhcp_settings(self._make_http_request_read('tcpiplan.asp'))

    @property
    def supports_reboot(self):
        return False

    def reboot(self):
        pass


def _parse_router_info(contents):
    obj = RouterInfo()
    obj.set_firmware_version(_parse_firmware_version(contents))
    obj.set_hardware_version("Unknown")
    return obj


def _parse_firmware_version(html):
    regex = "Firmware Version</b></td>(?:.+?)<td width=60%><font size=2>([a-zA-Z0-9-\.\(\)\s,]+)</td>"
    regex_firmware = re.compile(regex, re.DOTALL)

    match_object = regex_firmware.search(html)
    if match_object is None:
        raise RouterParseError("Cannot _parse firmware version")

    return match_object.group(1)


def _parse_uptime_to_seconds(html):
    regex = "Uptime</b></td>(?:.+?)<td width=60%><font size=2>([0-9]+)day:([0-9]+)h:([0-9]+)m:([0-9]+)s</td>"
    regex_uptime = re.compile(regex, re.DOTALL)

    match_object = regex_uptime.search(html)

    if match_object is None:
        raise RouterParseError("Cannot _parse uptime")

    days, hours, minutes, seconds = map(int, match_object.groups())

    return days * 86400 + hours * 3600 + minutes * 60 + seconds


def _parse_traffic_stats(contents):
    regex = "Ethernet WAN(?:.+?)Sent Packets(?:.+?)<font size=2>([0-9]+)</td>(?:.+?)Received Packets(?:.+?)<font size=2>([0-9]+)</td>"
    regex_traffic_stats = re.compile(regex, re.DOTALL)

    match_object = regex_traffic_stats.search(contents)
    if match_object is None:
        raise RouterParseError("Cannot _parse traffic stats")

    packets_recv, packets_sent = map(int, match_object.groups())
    # sadly, we've got only packets and no size information..
    return TrafficStats(0, 0, packets_recv, packets_sent)


def _parse_mac_address(contents):
    regex = "bssid_drv\[0\] ='((?:(?:[a-f0-9]{2}:){5})(?:[a-f0-9]{2}))';"
    regex_mac_address = re.compile(regex, re.DOTALL)

    match_object = regex_mac_address.search(contents)

    if match_object is None:
        raise RouterParseError("Cannot _parse mac address from contents")

    mac = match_object.group(1).strip(" ")
    if not validator.is_valid_mac_address(mac):
        raise RouterParseError("Found an invalid MAC address: %s" % mac)

    return converter.normalize_mac(mac)


def _parse_dns_servers(contents):
    regex = "name=\"dns[0-9]\"(?:.+?)value=(.*?)></td>"
    regex_dns_servers = re.compile(regex, re.DOTALL)

    servers = re.findall(regex_dns_servers, contents)
    return [ip.strip(" ") for ip in servers if validator.is_valid_ip_address(ip)]


def _parse_connected_clients_list(contents):
    regex = "<form(?:.+?)<tr(?:.+?)<tr bgcolor=(?:.+?)<font size=2>(.+?)</td><td><font size=2>(.+?)</td><td><font size=2>([0-9]+)</td>"
    regex_dhcp_list = re.compile(regex, re.DOTALL)

    lst = ConnectedClientsList()

    for id, match_groups in enumerate(re.findall(regex_dhcp_list, contents), start=1):
        ip, mac, lease_time = match_groups

        if not validator.is_valid_ip_address(ip):
            raise RouterParseError("Invalid IP address: %s" % ip)

        if not validator.is_valid_mac_address(mac):
            raise RouterParseError("Invalid MAC address: %s" % mac)

        lease_time = int(lease_time)

        item = ConnectedClientsListItem()
        item.set_client_name("Client %d" % id)
        item.set_mac(converter.normalize_mac(mac))
        item.set_ip(ip)

        item.set_lease_time(lease_time)

        lst.append(item)

    return lst


def _parse_wireless_settings(html_basic, html_advanced, html_security, html_wep):
    settings = WirelessSettings()
    settings.add_security_support(WirelessSettings.SECURITY_TYPE_WEP64)
    settings.add_security_support(WirelessSettings.SECURITY_TYPE_WEP128)
    settings.add_security_support(WirelessSettings.SECURITY_TYPE_WPA)
    settings.add_security_support(WirelessSettings.SECURITY_TYPE_WPA2)


    match_object = re.compile("var wps_ssid_old='(.+?)';").search(html_basic)
    if match_object is None:
        raise RouterParseError("Cannot find SSID!")
    settings.set_ssid(match_object.group(1))

    match_object = re.compile("var wps_disabled=(0|1);").search(html_basic)
    if match_object is None:
        raise RouterParseError("Cannot determine wireless enabled status!")
    settings.set_enabled_status(match_object.group(1) == "0")

    match_object = re.compile("defaultChan\[wlan_idx\]=(.+?);").search(html_basic)
    if match_object is None:
        raise RouterParseError("Cannot determine wireless channel!")
    settings.set_channel(int(match_object.group(1)))

    if "name=\"hiddenSSID\" value=\"no\"checked" not in html_advanced:
        settings.set_ssid_broadcast_status(False)


    # This is the security type (WEP, WPA, WPA2..)
    match_object = re.compile("var wps_encrypt_old=([0-4]);").search(html_security)
    if match_object is None:
        raise RouterParseError("Cannot determine security type!")
    security_type = int(match_object.group(1))

    if security_type == 1: # WEP
        match_object = re.compile("var wps_wep_keylen_old='([1-2])';").search(html_wep)
        if match_object is None:
            raise RouterParseError("Cannot determine WEP key length!")

        if int(match_object.group(1)) == 1: # 64bit
            settings.set_security_type(settings.__class__.SECURITY_TYPE_WEP64)
        else: # 128bit or something new that we don't handle
            settings.set_security_type(settings.__class__.SECURITY_TYPE_WEP128)
    elif security_type == 2: # WPA-PSK
        settings.set_security_type(settings.__class__.SECURITY_TYPE_WPA)
    elif security_type == 4: # WPA2-PSK
        settings.set_security_type(settings.__class__.SECURITY_TYPE_WPA2)
    else: # Either 0=No security or something else, which we don't handle
        settings.set_security_type(settings.__class__.SECURITY_TYPE_NONE)

    if settings.security_type_is_wpa:
        match_object = re.compile("var wps_psk_old='(.+?)';").search(html_security)
        if match_object is None:
            raise RouterParseError('Cannot determine wireless password!')
        settings.set_password(match_object.group(1))
    elif settings.security_type_is_wep:
        # WEP passwords are rendered as '****' on the page
        settings.set_password(None)
    else: # No security or something else
        settings.set_password("")

    return settings


def _parse_dhcp_settings(html):
    settings = DHCPServerSettings()
    settings.set_enabled_status('<option selected value="2">Server</option>' in html)

    match_object = re.compile('<input type="text" name="dhcpRangeStart" size="12" maxlength="15" value="(.+?)">').search(html)
    if match_object is None:
        raise RouterParseError("Cannot determine DHCP start IP")
    settings.set_ip_start(match_object.group(1))

    match_object = re.compile('<input type="text" name="dhcpRangeEnd" size="12" maxlength="15" value="(.+?)">').search(html)
    if match_object is None:
        raise RouterParseError("Cannot determine DHCP end IP")
    settings.set_ip_end(match_object.group(1))

    settings.ensure_valid()

    return settings


def _generate_wireless_data_basic(settings):
    settings.ensure_valid()

    data = {}

    data['wps_clear_configure_by_reg0'] = 0 # this is a hardcoded hidden field.. i don't know what it's for
    data['wlan-url'] = '/wlbasic.asp' # this is the 'redirect here when finished' url
    data['save'] = 'Save Settings'
    data['basicrates0'] = 0 # this is a hardcoded hidden field.. i don't know what it's for
    data['operrates0'] = 0 # this is a hardcoded hidden field.. i don't know what it's for

    data['band0'] = 2 # 2 means B+G mode
    data['mode0'] = 0 # 0 means 'operate in AccessPoint mode'
    data['ssid0'] = settings.ssid
    data['chan0'] = settings.channel

    if not settings.is_enabled:
        data['wlanDisabled0'] = 'ON'

    return data


def _generate_wireless_data_advanced(settings):
    settings.ensure_valid()

    data = {}

    data['authType'] = 'both' # Authentication Type (could be open/shared/both)
    data['fragThreshold'] = 2346 # Fragment Threshold (int from 256 to 2346)
    data['rtsThreshold'] = 2347 # RTS Threshold (int from 0 to 2347)
    data['beaconInterval'] = 100 # Beacon interval in milliseconds
    data['txRate'] = 0 # Data rate speed (0 = Auto)
    data['preamble'] = 'long' # Preamble Type (could be long/short)
    data['hiddenSSID'] = 'no' if settings.is_broadcasting_ssid else 'yes'
    data['iapp'] = 'yes' # IAPP (could be yes/no)
    data['11g_protection'] = 'yes' # 802.11g Protection (could be yes/no)
    data['wmm'] = 'off' # WMM (could be on/off)
    data['RFPower'] = 0 # 0 means 100% power
    data['turbo'] = 'auto' # Turbo Mode (could auto/always/off)
    data['save'] = 'Save Settings'
    data['submit-url'] = '/wladvanced.asp'

    return data


def _generate_wireless_data_security(settings):
    settings.ensure_valid()

    data = {}
    data['wps_clear_configure_by_reg0'] = '0'
    data['submit-url'] = '/wlwpa.asp'
    data['save'] = 'Save Settings'

    if settings.security_type_is_wep:
        data['method0'] = 1
    elif settings.security_type_is_wpa:
        # specifies whether we're using Personal or Radius auth
        data['wpaAuth0'] = 'psk'
        data['pskFormat0'] = '0' # 0 = passphrase; 1 = hex passphrase only
        data['pskValue0'] = settings.password
        if settings.security_type == settings.__class__.SECURITY_TYPE_WPA:
            data['method0'] = 2
            data['ciphersuite0'] = 'tkip'
        else:
            data['method0'] = 4
            data['wpa2ciphersuite0'] = 'aes'
    else: # no security
        data['method0'] = 0

    return data


def _generate_wireless_data_wep(settings):
    settings.ensure_valid()

    if not settings.security_type_is_wep:
        raise RuntimeError("Cannot generate WEP data from non-WEP settings")

    data = {}
    data['wps_clear_configure_by_reg0'] = '0'
    data['submit-url'] = '/wlwep.asp'
    data['save'] = 'Save Settings'
    # I think this field has the side effect
    # of enabling WEP, if it was disabled before..
    data['wepEnabled0'] = 'ON'
    data['length0'] = 1 if settings.security_type == settings.__class__.SECURITY_TYPE_WEP64 else 2
    data['format0'] = 2 if settings.is_wep_password_in_hex else 1
    data['defaultTxKeyId0'] = 1 # which WEP key is the default
    data['key10'] = settings.password
    data['key20'] = ''
    data['key30'] = ''
    data['key40'] = ''

    return data

