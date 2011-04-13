import re
import base64

from roscraco.router.base import RouterBase

from roscraco.helper import validator, converter
from roscraco.exception import RouterFetchError, RouterParseError, \
     RouterIdentityError

from roscraco.response import RouterInfo, TrafficStats, DMZSettings, \
     ConnectedClientsListItem, ConnectedClientsList, WirelessSettings, \
     DHCPReservationList, DHCPReservationListItem, DHCPServerSettings


class Zyxel_P330W(RouterBase):

    def _perform_http_request(self, *args, **kwargs):
        auth = base64.b64encode('%s:%s' % (self.username, self.password))
        kwargs['headers'] = [('Authorization', 'Basic %s' % auth)]
        return RouterBase._perform_http_request(self, *args, **kwargs)

    def _wait_for_settings_reload(self, wait_time=32):
        """Blocks until the router reloads its settings
        and becomes ready to respond to requests again.
        """
        from time import sleep
        sleep(wait_time)

    def confirm_identity(self):
        try:
            html = self._make_http_request_read('status.asp')
            if '<title>Wireless Router Status</title>' not in html:
                raise RouterIdentityError(
                    'Cannot confirm that this is a router!'
                )
            # would raise RouterParseError if it fails
            self.get_router_info()
        except (RouterParseError, RouterFetchError):
            raise RouterIdentityError('Cannot confirm identity!')

    def get_router_info(self):
        return _parse_router_info(self._make_http_request_read('status.asp'))

    def get_uptime(self):
        return None

    def get_pppoe_online_time(self):
        return None

    def get_traffic_stats(self):
        html = self._make_http_request_read('stats.asp')
        return _parse_traffic_stats(html)

    def get_mac_address(self):
        html = self._make_http_request_read('status.asp')
        return _parse_mac_address(html)

    def get_dns_servers(self):
        # We cannot determine DNS servers that are automatically
        # assigned (for PPPoE connections), so this can only be made
        # to work for manually added DNS server entries.
        # These are rare cases, so we won't bother for now.
        return []

    def get_connected_clients_list(self):
        html = self._make_http_request_read('dhcptbl.asp')
        return _parse_connected_clients_list(html)

    def get_dmz_settings(self):
        html = self._make_http_request_read('dmz.asp')
        return _parse_dmz_settings(html)

    def push_dmz_settings(self, settings):
        settings_old = self.get_dmz_settings()
        if settings == settings_old:
            return True

        data = _generate_dmz_data(settings)
        # The router reloads its settings as we make the request,
        # so it's normal for it to take about 10 seconds
        self._make_http_request_write('goform/formDMZ', data, timeout=15.0)

        new = self.get_dmz_settings()
        if settings.is_enabled:
            # We can push a full update when it's enabled
            return new == settings
        else:
            # We can only switch the enabled status, but
            # can't change the IP when disabling..
            return settings.is_enabled == new.is_enabled

    def get_dhcp_settings(self):
        html = self._make_http_request_read('tcpiplan.asp')
        return _parse_dhcp_settings(html)

    def get_addr_reservation_list(self):
        html = self._make_http_request_read('tcpiplan.asp')
        return _parse_addr_reservation_list(html)

    def push_addr_reservation_list(self, lst_new):
        lst_new.ensure_valid()

        lst_old = self.get_addr_reservation_list()
        if lst_old == lst_new:
            return True

        if len(lst_old) != 0:
            delete = {}
            delete['delallLease'] = 'Delete All'
            delete['submit-url'] = '/tcpiplan.asp'
            delete['submit-value'] = '0.031'
            self._make_http_request_write('goform/formStaticLease', delete)
            self._wait_for_settings_reload()

        for item in lst_new:
            data = _generate_addr_reservation_item_data(item)
            self._make_http_request_write('goform/formStaticLease', data)
            self._wait_for_settings_reload()

        return self.get_addr_reservation_list() == lst_new

    def get_wireless_settings(self):
        html = [self._make_http_request_read(path) for path in (
            'wlbasic.asp', 'wladvanced.asp', 'wlwpa.asp', 'wlwep.asp'
        )]
        return _parse_wireless_settings(*html)

    def push_wireless_settings(self, settings):
        # Each time a settings update is pushed (to whatever page)
        # the router reloads its settings (which takes a lot of time).
        # It was possible to do multiple pushes one after another and
        # get by with only one settings reload, but one of the test routers
        # crashed when that was done. So we'll play it safe and wait each time.
        # To get around the slow updates, we only push updates to a page
        # that has changes.
        settings_old = self.get_wireless_settings()

        if settings.channel != settings_old.channel or \
           settings.ssid != settings_old.ssid:
            basic = _generate_wireless_data_basic(settings)
            self._make_http_request_write('goform/formWlanSetup', basic)
            self._wait_for_settings_reload()

        if settings.is_broadcasting_ssid != settings_old.is_broadcasting_ssid:
            advanced = _generate_wireless_data_advanced(settings)
            self._make_http_request_write('goform/formAdvanceSetup', advanced)
            self._wait_for_settings_reload()

        if settings.security_type_is_wep and \
           settings.password != settings_old.password:
            wep = _generate_wireless_data_wep(settings)
            self._make_http_request_write('goform/formWep', wep)
            self._wait_for_settings_reload()

        if settings.security_type != settings_old.security_type or \
           (settings.security_type_is_wpa and \
            settings.password != settings_old.password):
            security = _generate_wireless_data_security(settings)
            self._make_http_request_write('goform/formWlEncrypt', security)
            self._wait_for_settings_reload()

        return settings.eq(self.get_wireless_settings(), skip_attrs=('password',))

    @property
    def supports_reboot(self):
        return False

    def reboot(self):
        pass

def _parse_router_info(html):
    obj = RouterInfo()
    obj.set_hardware_version('P-330W EE')
    match_object = re.compile('>(P-330W_EE_(?:.+?))</font>').search(html)
    if match_object is None:
        raise RouterParseError('Cannot determine firmware version!')
    obj.set_firmware_version(match_object.group(1))
    return obj


def _parse_traffic_stats(html):
    regex = re.compile('Ethernet WAN(?:.+?)<td>([0-9]+)</td>'
                       '(?:.+?)<td>([0-9]+)</td>', re.DOTALL)
    match_object = regex.search(html)
    if match_object is None:
        raise RouterParseError('Cannot determine WAN stats!')
    packets_sent, packets_recv = map(int, match_object.groups())
    return TrafficStats(0, 0, packets_recv, packets_sent)


def _parse_mac_address(html):
    regex = re.compile('<!--Wan Information-->(?:.+?)Physical Address(?:.+?)'
                       '>((?:[a-f0-9]{2}:){5}[a-f0-9]{2})</font>', re.DOTALL)
    match_object = regex.search(html)
    if match_object is None:
        raise RouterParseError('Cannot determine MAC address!')
    return converter.normalize_mac(match_object.group(1))


def _parse_connected_clients_list(html):
    lst = ConnectedClientsList()

    regex = re.compile('<tr bgcolor=#(?:.+?)><td><font size=2>(.+?)</td>'
                       '<td><font size=2>(.+?)</td>'
                       '<td><font size=2>([0-9]+)</td></tr>')
    for i, (ip, mac, time) in enumerate(regex.findall(html)):
        item = ConnectedClientsListItem()
        item.set_client_name('Client %d' % (i + 1))
        item.set_ip(ip)
        item.set_mac(converter.normalize_mac(mac))
        item.set_lease_time(int(time))
        lst.append(item)
    return lst


def _parse_dmz_settings(html):
    settings = DMZSettings()
    settings.set_reboot_requirement_status(False)
    settings.set_supported_status(True)
    enabled = '<input type=checkbox name="enabled" value="ON" checked' in html
    settings.set_enabled_status(enabled)
    regex = re.compile('<input type=text name="ip" size=15'
                      ' maxlength=16 value="(.+?)"')
    match_object = regex.search(html)
    if match_object is None:
        raise RouterParseError('Cannot determine DMZ IP!')
    ip = match_object.group(1)
    if not validator.is_valid_ip_address(ip):
        if not enabled:
            ip = '192.168.1.1' # sane default value
        else:
            raise RouterParseError('Invalid IP address!')
    settings.set_ip(ip)
    return settings


def _parse_dhcp_settings(html):
    is_enabled = 'var choice= 2 ;' in html

    regex = re.compile('<input type=text name="dhcpRangeStart" size=16 '
                       'maxlength=15 value="(.+?)"'
                       '(?:.+?)'
                       '<input type=text name="dhcpRangeEnd" size=16 '
                       'maxlength=15 value="(.+?)"', re.DOTALL)
    match_object = regex.search(html)
    if match_object is None:
        raise RouterParseError('Cannot determine DMZ range!')
    for ip in match_object.groups():
        if not validator.is_valid_ip_address(ip):
            raise RouterParseError('Invalid DHCP IP: %s' % ip)

    ip_start, ip_end = match_object.groups()
    obj = DHCPServerSettings()
    obj.set_enabled_status(is_enabled)
    obj.set_ip_start(ip_start)
    obj.set_ip_end(ip_end)
    obj.ensure_valid()
    return obj


def _parse_addr_reservation_list(html):
    lst = DHCPReservationList()
    lst.set_reboot_requirement_status(False)
    regex = re.compile('<tr><td align=center width="50%" bgcolor="#C0C0C0">'
                       '<font size="2">(.+?)</td>(?:.+?)'
                       '<font size="2">(.+?)</td>(?:.+?)'
                       'name="select[0-9]+"', re.DOTALL)
    for mac, ip in regex.findall(html):
        item = DHCPReservationListItem()
        item.set_mac(mac)
        item.set_ip(ip)
        lst.append(item)
    return lst


def _parse_wireless_settings(html_basic, html_advanced, html_security, html_wep):
    settings = WirelessSettings()
    settings.add_security_support(WirelessSettings.SECURITY_TYPE_WEP64)
    settings.add_security_support(WirelessSettings.SECURITY_TYPE_WEP128)
    settings.add_security_support(WirelessSettings.SECURITY_TYPE_WPA)
    settings.add_security_support(WirelessSettings.SECURITY_TYPE_WPA2)
    settings.set_reboot_requirement_status(False)

    markup = '<input type=checkbox name="wlanDisabled0" value="ON" checked'
    settings.set_enabled_status(markup not in html_basic)

    regex = re.compile('defaultChan\[wlan_idx\]=([0-9]+);')
    match_object = regex.search(html_basic)
    if match_object is None:
        raise RouterParseError('Cannot determine channel.')
    settings.set_channel(int(match_object.group(1)))

    regex = re.compile('<input type=text name="ssid0" size=33 '
                       'maxlength=32 value="(.+?)"')
    match_object = regex.search(html_basic)
    if match_object is None:
        raise RouterParseError('Cannot determine SSID.')
    settings.set_ssid(match_object.group(1))

    markup = '<input type=radio name="hiddenSSID" value="no"checked>'
    settings.set_ssid_broadcast_status(markup in html_advanced)

    if '<option selected value=1>WEP' in html_security:
        passwords = re.compile('form.key10.value = "(.*?)";').findall(html_wep)
        # We expect 3 matches: 1) irrelevant 2) wep128 pass 3) wep64 pass
        if len(passwords) != 3:
            raise RouterParseError('Wrong number of passwords retrieved:'
                                   ' %d' % len(passwords))
        key_len_64 = '<input type=radio name="wepKeyLen0" value="wep64" checked>'
        if key_len_64 in html_security:
            settings.set_security_type(WirelessSettings.SECURITY_TYPE_WEP64)
            settings.set_password(passwords[2])
        else:
            settings.set_security_type(WirelessSettings.SECURITY_TYPE_WEP128)
            settings.set_password(passwords[1])
    elif '<option selected value=2>WPA' in html_security:
        settings.set_security_type(WirelessSettings.SECURITY_TYPE_WPA)
    elif '<option selected value=4>WPA2' in html_security:
        settings.set_security_type(WirelessSettings.SECURITY_TYPE_WPA2)
    else:
        settings.set_security_type(WirelessSettings.SECURITY_TYPE_NONE)

    return settings


def _generate_wireless_data_basic(settings):
    settings.ensure_valid()
    data = {}
    data['wlan-url'] = '/wlbasic.asp'
    data['submit-value'] = '0.031' # i don't know what it's for
    data['save'] = 'Save'
    data['basicrates0'] = 0 # i don't know what it's for
    data['operrates0'] = 0 # i don't know what it's for
    data['band0'] = 2 # 2 means B+G mode
    data['mode0'] = 0 # 0 means 'operate in AccessPoint mode'
    data['ssid0'] = settings.ssid
    data['chan0'] = settings.channel
    data['txRate'] = 0 # data rate = Auto
    data['wifiTestEnabled0'] = ''
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
    data['preamble'] = 'long' # Preamble Type (could be long/short)
    data['hiddenSSID'] = 'no' if settings.is_broadcasting_ssid else 'yes'
    data['iapp'] = 'yes' # IAPP (could be yes/no)
    data['11g_protection'] = 'no' # 802.11g Protection (could be yes/no)
    data['save'] = 'Save'
    data['submit-url'] = '/wladvanced.asp'
    data['submit-value'] = '0.031'
    return data


def _generate_wireless_data_wep(settings):
    settings.ensure_valid()

    if not settings.security_type_is_wep:
        raise RuntimeError("Cannot generate WEP data from non-WEP settings")

    data = {}
    data['submit-url'] = '/wlwep.asp'
    data['submit-value'] = '0.031'
    data['save'] = 'Save'
    data['autogen_key'] = ''
    data['actionType'] = 0
    # I think this field has the side effect
    # of enabling WEP, if it was disabled before..
    data['wepEnabled0'] = 'ON'
    is_64 = settings.security_type == settings.__class__.SECURITY_TYPE_WEP64
    data['length0'] = 1 if is_64 else 2
    data['format0'] = 2 if settings.is_wep_password_in_hex else 1
    data['defaultTxKeyId0'] = 1 # which WEP key is the default
    data['key10'] = settings.password
    data['key20'] = ''
    data['key30'] = ''
    data['key40'] = ''
    return data


def _generate_wireless_data_security(settings):
    settings.ensure_valid()

    data = {}
    data['submit-url'] = '/wlwpa.asp'
    data['submit-value'] = '0.031'
    data['save'] = 'Save'
    if settings.security_type_is_wep:
        data['method0'] = 1
    elif settings.security_type_is_wpa:
        # specifies whether we're using Personal or Radius auth
        data['wpaAuth0'] = 'psk'
        data['pskFormat0'] = '0' # 0 = passphrase; 1 = hex passphrase only
        data['pskValue0'] = settings.password
        data['lifeTime0'] = 86400
        if settings.security_type == settings.__class__.SECURITY_TYPE_WPA:
            data['method0'] = 2
            data['ciphersuite0'] = 'tkip'
        else:
            data['method0'] = 4
            data['wpa2ciphersuite0'] = 'aes'
    else: # no security
        data['method0'] = 0
    return data


def _generate_dmz_data(settings):
    settings.ensure_valid()
    data = {}
    data['submit-url'] = '/dmz.asp'
    data['save'] = 'Save'
    if settings.is_enabled:
        data['enabled'] = 'ON'
        data['ip'] = settings.ip
    return data


def _generate_addr_reservation_item_data(item):
    data = {}
    data['addLease'] = 'Save'
    data['leaseIp'] = item.ip
    data['mac'] = item.mac
    data['submit-url'] = '/tcpiplan.asp'
    data['submit-value'] = '0.031'
    return data
