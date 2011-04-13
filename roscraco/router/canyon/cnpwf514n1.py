import re
import base64

from roscraco.router.base import RouterBase

from roscraco.helper import validator, converter
from roscraco.exception import RouterParseError, RouterIdentityError

from roscraco.response import RouterInfo, TrafficStats, DMZSettings, \
     ConnectedClientsListItem, ConnectedClientsList, WirelessSettings, \
     DHCPReservationList, DHCPReservationListItem, DHCPServerSettings


class Canyon_CNPWF514N1(RouterBase):

    def _perform_http_request(self, *args, **kwargs):
        auth = base64.b64encode('%s:%s' % (self.username, self.password))
        kwargs['headers'] = [('Authorization', 'Basic %s' % auth)]
        return RouterBase._perform_http_request(self, *args, **kwargs)

    def confirm_identity(self):
        _, headers, contents = self._perform_http_request('%sindex.asp' %
                                                          self.url_base)

        header_server = headers.getheader('Server')
        if header_server != 'GoAhead-Webs':
            raise RouterIdentityError('Invalid Server header: %s' % header_server)

        string_to_find = '/file/multilanguage.var'
        if string_to_find not in contents:
            raise RouterIdentityError('Cannot find string in contents: %s' % string_to_find)

    def get_router_info(self):
        return _parse_router_info(self._make_http_request_read('stainfo.asp'))

    def get_uptime(self):
        return _parse_uptime(self._make_http_request_read('stainfo.asp'))

    def get_pppoe_online_time(self):
        return None

    def get_traffic_stats(self):
        return _parse_traffic_stats(self._make_http_request_read('stats.asp'))

    def get_mac_address(self):
        return _parse_mac_address(self._make_http_request_read('stanet.asp'))

    def get_dns_servers(self):
        return _parse_dns_servers(self._make_http_request_read('stanet.asp'))

    def get_connected_clients_list(self):
        # What's interesting about this router is that the DHCP list
        # shows LAN clients only (and not Wi-Fi clients)
        # There's a separate list for Wi-Fi clients, but it shows on IPs,
        # so it's worthless..
        # The DHCP server (and address reservations) work on the LAN only!
        html = self._make_http_request_read('stadhcptbl.asp')
        return _parse_connected_clients_list(html)

    def get_dmz_settings(self):
        # DMZ not supported at all
        settings = DMZSettings()
        settings.set_supported_status(False)
        settings.set_enabled_status(False)
        settings.set_ip('0.0.0.0')
        return settings

    def push_dmz_settings(self, settings):
        pass

    def get_dhcp_settings(self):
        return _parse_dhcp_settings(self._make_http_request_read('lan.asp'))

    def get_addr_reservation_list(self):
        return _parse_addr_reservations(self._make_http_request_read('lan.asp'))

    def push_addr_reservation_list(self, lst_new):
        lst_new.ensure_valid()

        lst_old = self.get_addr_reservation_list()

        if lst_old == lst_new:
            return True

        if len(lst_old) != 0:
            # delete all old entries at once, before we push the new entries
            data = _generate_addr_reservation_delete_data(lst_old)
            self._make_http_request_write('goform/formSDHCP', data)

        for item in lst_new:
            data = _generate_addr_reservation_add_data(item)
            self._make_http_request_write('goform/formSDHCP', data)

        return self.get_addr_reservation_list() == lst_new

    def get_wireless_settings(self):
        html = []
        html.append(self._make_http_request_read('wlmain.asp'))
        html.append(self._make_http_request_read('wlbasic.asp'))
        html.append(self._make_http_request_read('wladvance.asp'))
        html.append(self._make_http_request_read('wlencrypt.asp'))
        return _parse_wireless_settings(*html)

    def push_wireless_settings(self, settings):
        data_basic = _generate_wireless_data_basic(settings)
        self._make_http_request_write('goform/formWlanSetup', data_basic)

        data_advanced = _generate_wireless_data_advanced(settings)
        self._make_http_request_write('goform/formAdvanceSetup', data_advanced)

        data_security = _generate_wireless_data_security(settings)
        self._make_http_request_write('goform/formWlEncrypt', data_security)

        # We MUST update this last.. because it potentially DISABLES wireless
        # If we disable it, and push the above settings after that
        # the router will act smart and re-enable wireless again
        data_main = _generate_wireless_data_main(settings)
        self._make_http_request_write('goform/formWlEnable', data_main)

        settings_now = self.get_wireless_settings()

        if not settings.security_type_is_wep:
            return settings_now == settings

        # We're changing to WEP security, and we can't extract WEP passwords
        # so we need some custom validation
        return settings_now.eq(settings, skip_attrs=('password', )) and settings_now.password is None

    @property
    def supports_reboot(self):
        return True

    def reboot(self):
        data = {'reset_flag': 0, 'submit-url': '/tlreset.asp'}
        self._make_http_request_write('goform/formReboot', data)


def _parse_router_info(html):
    info = RouterInfo()

    match_object = re.compile("dw\(HardwareVersion\)(?:.+?)table2(?:.+?)>&nbsp;(.+?)</td>", re.DOTALL).search(html)
    if match_object is None:
        raise RouterParseError('Cannot determine hardware version')
    info.set_hardware_version(match_object.group(1))

    match_object = re.compile("dw\(RuntimeCodeVersion\)(?:.+?)table2(?:.+?)>&nbsp;(.+?)</td>", re.DOTALL).search(html)
    if match_object is None:
        raise RouterParseError('Cannot determine hardware version')
    info.set_firmware_version(match_object.group(1))

    return info


def _parse_uptime(html):
    regex = re.compile("dw\(UpTime\)(?:.+?)table2(?:.+?)&nbsp;([0-9]+)day:([0-9]+)h:([0-9]+)m:([0-9]+)s</td>", re.DOTALL)
    match_object = regex.search(html)
    if match_object is None:
        raise RouterParseError('Cannot _parse uptime')

    days, hours, minutes, seconds = map(int, match_object.groups())

    return days * 86400 + hours * 3600 + minutes * 60 + seconds


def _parse_traffic_stats(html):
    regex = "showText\(EthernetWAN\)(?:.+?)table2(?:.+?)&nbsp;([0-9]+)(?:.+?)table2(?:.+?)&nbsp;([0-9]+)"
    match_object = re.compile(regex, re.DOTALL).search(html)
    if match_object is None:
        raise RouterParseError('Cannot _parse traffic stats')

    packets_sent, packets_recv = map(int, match_object.groups())
    # sadly, we've got only packets and no size information..
    return TrafficStats(0, 0, packets_recv, packets_sent)


def _parse_mac_address(html):
    match_object = re.compile("dw\(MACAddress\)(?:.+?)table2(?:.+?)>&nbsp;(.+?)\s", re.DOTALL).search(html)
    if match_object is None:
        raise RouterParseError('Cannot determine mac address')

    mac = match_object.group(1).strip(" ")
    if not validator.is_valid_mac_address(mac):
        raise RouterParseError('Found an invalid MAC address: %s' % mac)

    return converter.normalize_mac(mac)


def _parse_dns_servers(html):
    regex_dns_servers = re.compile('name="dns[1,2]" value="(.+?)\s')
    servers = re.findall(regex_dns_servers, html)
    return [ip.strip(" ") for ip in servers if validator.is_valid_ip_address(ip)]


def _parse_connected_clients_list(html):
    regex_dhcp_list = "<tr class=table2 align=center><td><font size=2>(.+?)</td><td><font size=2>(.+?)</td>"
    lst = ConnectedClientsList()

    for id, (ip, mac) in enumerate(re.findall(regex_dhcp_list, html), start=1):
        if ip == "None":
            # this entry is added when there are no connected clients
            break

        if not validator.is_valid_ip_address(ip):
            raise RouterParseError('Invalid IP address: %s' % ip)

        if not validator.is_valid_mac_address(mac):
            raise RouterParseError('Invalid MAC address: %s' % mac)

        item = ConnectedClientsListItem()
        item.set_client_name('Client %d' % id)
        item.set_mac(converter.normalize_mac(mac))
        item.set_ip(ip)
        item.set_lease_time(0)

        lst.append(item)

    return lst


def _parse_dhcp_settings(html):
    regex = re.compile('name="dhcpRange(?:Start|End)" size="15" maxlength="15" value="(.+?)"')
    try:
        ip_start, ip_end = regex.findall(html)
    except ValueError:
        raise RouterParseError('Cannot find DHCP start/end range')
    else:
        settings = DHCPServerSettings()
        settings.set_ip_start(ip_start)
        settings.set_ip_end(ip_end)
        settings.set_enabled_status('<option selected value="2"><script>dw(Enable)</script></option>' in html)
        settings.ensure_valid()

        return settings


def _parse_addr_reservations(html):
    regex = re.compile('name="smac[0-9]+" value="(.+?)"(?:.+?)name="sip[0-9]+" value="(.+?)">', re.DOTALL)

    reservation_list = DHCPReservationList()
    reservation_list.set_reboot_requirement_status(False)

    for mac, ip in regex.findall(html):
        item = DHCPReservationListItem()
        item.set_mac(converter.normalize_mac(mac))
        item.set_ip(ip)
        item.set_enabled_status(True)
        reservation_list.append(item)
    return reservation_list


def _parse_wireless_settings(html_main, html_basic, html_advanced, html_security):
    obj = WirelessSettings()
    obj.add_security_support(WirelessSettings.SECURITY_TYPE_WEP64)
    obj.add_security_support(WirelessSettings.SECURITY_TYPE_WEP128)
    obj.add_security_support(WirelessSettings.SECURITY_TYPE_WPA)
    obj.add_security_support(WirelessSettings.SECURITY_TYPE_WPA2)

    obj.set_auto_channel_support(False)

    # the naming of the radio button is weird!
    is_enabled = '<input type="radio" name="wlanDisabled" value="yes" checked>' in html_main
    obj.set_enabled_status(is_enabled)


    match_object = re.compile('document.wlanSetup.ssid.value="(.+?)";').search(html_basic)
    if match_object is None:
        raise RouterParseError('Cannot determine SSID')
    obj.set_ssid(match_object.group(1))

    match_object = re.compile('var defaultChan = ([0-9]+)[\s\n]').search(html_basic)
    if match_object is None:
        raise RouterParseError('Cannot determine channel')
    obj.set_channel(int(match_object.group(1)))

    is_broadcasting_ssid = '<input type="radio" name="hiddenSSID" value="no" checked>' in html_advanced
    obj.set_ssid_broadcast_status(is_broadcasting_ssid)

    match_object = re.compile('methodVal = ([0-3]);').search(html_security)
    if match_object is None:
        raise RouterParseError('Cannot determine security type')
    security_type = int(match_object.group(1))
    if security_type == 0:
        obj.set_security_type(obj.__class__.SECURITY_TYPE_NONE)
    elif security_type == 1: # WEP of some sort
        match_object = re.compile('var wepTbl =\s+new Array\("([0-9]+)"\);').search(html_security)
        if match_object is None:
            raise RouterParseError('Cannot determine WEP bit length')
        if int(match_object.group(1)) in (0, 1):
            obj.set_security_type(obj.__class__.SECURITY_TYPE_WEP64)
        else:
            obj.set_security_type(obj.__class__.SECURITY_TYPE_WEP128)

        # WEP passwords cannot be extracted! It shows "***" only
    elif security_type == 2: # WPA of some sort
        match_object = re.compile('var wpaCipherTbl =(?:\s+)?new Array\("([0-9]+)"\);').search(html_security)
        if match_object is None:
            raise RouterParseError('Cannot determine WPA type')
        if int(match_object.group(1)) in (0, 1, 3): # 0, 1 = WPA; 3 = mixed
            obj.set_security_type(obj.__class__.SECURITY_TYPE_WPA)
        else: # all other values are WPA2 only
            obj.set_security_type(obj.__class__.SECURITY_TYPE_WPA2)

        match_object = re.compile('var pskValueTbl = new Array\("(.+?)"\);').search(html_security)
        if match_object is None:
            raise RouterParseError('Cannot determine WPA password')
        obj.set_password(match_object.group(1))
    else: # 3 = WPA Radius
        raise NotImplementedError('Security type not supported')

    return obj


def _generate_addr_reservation_delete_data(lst_old):
    if len(lst_old) == 0:
        raise Exception('Nothing to delete!')

    data = {}
    data['deleteAllDhcpMac'] = 'Delete All'
    data['submit-url'] = '/lan.asp'
    data['smacnum'] = len(lst_old)

    for i, item in enumerate(lst_old, start=1):
        data['sip%d' %i] = item.ip
        data['smac%d' %i] = item.mac

    return data


def _generate_addr_reservation_add_data(item):
    data = {}
    data['SDHCPEnabled'] = 'ON'
    data['addSDHCPMac'] = 'Add'
    data['submit-url'] = '/lan.asp'
    data['tiny_idx'] = 0
    data['ip'] = item.ip
    data['mac'] = item.mac
    return data


def _generate_wireless_data_main(settings):
    settings.ensure_valid()

    data = {'wlan-url': '/wlmain.asp'}

    # yes.. this seems backwards! bad field/value naming on Canyon's part!
    data['wlanDisabled'] = 'yes' if settings.is_enabled else 'no'

    return data


def _generate_wireless_data_basic(settings):
    settings.ensure_valid()

    data = {'B1': 'APPLY', 'wlan-url': '/wlbasic.asp'}
    data['apMode'] = '0' # 0 = Access Point (normal mode..)

    data['band'] = 4 # 0 = B; 1 = N; 2 = B+G; 3 = G; 4 = B+G+N
    data['chan'] = settings.channel
    data['ssid'] = settings.ssid

    # Repeater-Mode related settings.. we don't support this
    data['repeaterSSID'] = ''
    data['autoMacClone'] = 'no'
    data['wisp'] = 0
    data['macAddrValue'] = ''

    # Universal Wireless Repeater related stuff..
    data['wlLinkMac1'] = '000000000000'
    data['wlLinkMac2'] = '000000000000'
    data['wlLinkMac3'] = '000000000000'
    data['wlLinkMac4'] = '000000000000'
    data['wlanMac'] = '000000000000'

    # This should be 0 if the SSID remains the same
    # and 1 if it has changed..
    # Unfortunately, we don't know what the previous value is,
    # so let's supply 1.. it seems to work fine
    data['wpsStatus'] = 1

    return data


def _generate_wireless_data_advanced(settings):
    settings.ensure_valid()

    data = {}

    # We're basically using "sane" settings everywhere
    # and are only changing the "Broadcast SSID" field
    # Things could be improved if the original settings were preserved
    # we can do that by setting "internal_params" on the WirelessSettings object
    # and using their original values here
    # .. maybe that's something @todo

    data['B1'] = 'APPLY'
    data['NtxRate'] = 0
    data['beaconInterval'] = 100
    data['disProtection'] = 'no'
    data['dtimPeriod'] = 3
    data['fragThreshold'] = 2346
    data['getRate'] = 'auto'
    data['getTxPower'] = 0
    data['hiddenSSID'] = 'no' if settings.is_broadcasting_ssid else 'yes'
    data['iapp'] = 'yes'
    data['ipnPrmb'] = 0
    data['preamble'] = 'long'
    data['rtsThreshold'] = 2347
    data['submit-url'] = '/wladvance.asp'
    data['txRate'] = 0
    data['wlanBurst'] = 'no'
    data['wlanCts'] = 'none'
    data['wlanNChanWidth'] = 0
    data['wlanRateMode'] = 'mixed'
    data['wlanTxPower'] = 0
    data['wlanWmm'] = 'no'

    return data


def _generate_wireless_data_security(settings):
    settings.ensure_valid()

    data = {}

    # Set default WEP keys.. to be changed later if in WEP mode
    data['key1'], data['key2'], data['key3'], data['key4'] = ('*' * 10,) * 4

    # Specify that the first WEP key is to be used
    data['defaultTxKeyId'] = 1

    if settings.security_type_is_wep:
        data['format'] = 2 if settings.is_wep_password_in_hex else 1
        data['key1'] = settings.password

        # bit length (64bit vs 128bit)
        data['length'] = 1 if settings.security_type == settings.__class__.SECURITY_TYPE_WEP64 else 2

        data['method'] = 1 # security_type = WEP
    else:
        data['format'] = 2
        data['length'] = 1

        if settings.security_type_is_wpa:
            data['method'] = 2 # for both WPA and WPA2
        else: # security is disabled or unsupported
            data['method'] = 0


    data['pskFormat'] = 0 # 0 = ASCII, 1 = HEX
    data['pskValue'] = settings.password

    # Unsupported WPA Radius auth settings
    data['radiusIP'], data['radiusPass'], data['radiusPort'] = '', '', 1812
    data['sel1xMode'] = 'ON'

    data['selected_ssid'] = 0 # has something to do with SSID presets and switching

    data['submit-url'] = '/wlencrypt.asp'

    # This is weird.. I've even seen it with WPA2
    data['wepEnabled'] = 'ON'

    # 1 = WPA; 2 = WPA2; 3 = WPA2 Mixed
    data['wpaCipher'] = 1 if settings.security_type == settings.__class__.SECURITY_TYPE_WPA else 2

    return data

