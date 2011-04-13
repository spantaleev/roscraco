import re
import base64

from roscraco.router.base import RouterBase

from roscraco.helper import validator, converter
from roscraco.exception import RouterFetchError, RouterParseError, \
     RouterIdentityError

from roscraco.response import RouterInfo, TrafficStats, DMZSettings, \
     ConnectedClientsListItem, ConnectedClientsList, WirelessSettings, \
     DHCPReservationList, DHCPReservationListItem, DHCPServerSettings


class NetgearWGR614Base(RouterBase):
    """Base class for all WGR614 routers, regardless of their version."""

    def __init__(self, *args, **kwargs):
        RouterBase.__init__(self, *args, **kwargs)
        self._is_logged_in = False

    def _perform_http_request(self, *args, **kwargs):
        auth = base64.b64encode('%s:%s' % (self.username, self.password))
        kwargs['headers'] = [('Authorization', 'Basic %s' % auth)]
        return RouterBase._perform_http_request(self, *args, **kwargs)

    def _handle_first_request(self):
        """We need to make an initial "login" request.

        The router will respond with 401 Unauthorized (RouterFetchError)
        to other requests if we start making requests directly.
        What we're doing here is making a request which catches that
        initial 401 error and simply ignores it.

        This function also does something else special for Netgear routers.
        The web management interface can be used from only one IP at a time.
        Access to the router is locked until the user logs out
        (handled in :meth:`close`) or his session expires.
        If the router replies with a non-401 response on our first request,
        it may be telling us that someone else is logged in and managing it.
        """
        try:
            contents = self._make_http_request_read('RST_status.htm')
        except RouterFetchError:
            # it's quite normal if we're here!
            pass
        else:
            # We got a good response, that's somewhat abnormal
            # It could mean that someone else is managing the device
            # Or that we're already "logged in" somehow
            if ') is managing this device' in contents:
                regex = re.compile('\((.+?)\) is managing this device')
                match_obj = regex.search(contents)
                ip = match_obj.group(1) if match_obj is not None else 'unknown'
                raise RouterFetchError('Device is managed by %s!' % ip)

    def close(self):
        # It's a good idea to perform a logout, because no one else
        # will be able to log in until the current session expires
        # (the session is on an IP basis)
        try:
            if self._is_logged_in:
                # Only logout if we've made at least one
                # successful request
                self._make_http_request_read('LGO_logout.htm')
                self._is_logged_in = False
        except RouterFetchError:
            pass

    def get_router_info(self):
        return _parse_router_info(self._make_http_request_read('RST_status.htm'))

    def get_uptime(self):
        return _parse_uptime_to_seconds(self._make_http_request_read('RST_stattbl.htm'))

    def get_traffic_stats(self):
        return _parse_traffic_stats(self._make_http_request_read('RST_stattbl.htm'))

    def get_pppoe_online_time(self):
        return _parse_pppoe_online_time(self._make_http_request_read('RST_st_poe.htm'))

    def get_mac_address(self):
        return _parse_mac_address(self._make_http_request_read('RST_status.htm'))

    def get_dns_servers(self):
        return _parse_dns_servers(self._make_http_request_read('RST_status.htm'))

    def get_connected_clients_list(self):
        return _parse_connected_clients_list(self._make_http_request_read('DEV_device.htm'))

    def _confirm_identity_meta_description(self, value):
        contents = self._perform_http_request('%sRST_status.htm' % self.url_base)[2]

        string_to_find = '<META name="description" content="%s' % value
        if string_to_find not in contents:
            raise RouterIdentityError('Cannot find string in contents: %s' % string_to_find)

    def get_dhcp_settings(self):
        return _parse_dhcp_settings(self._make_http_request_read('LAN_lan.htm'))

    def get_addr_reservation_list(self):
        return _parse_addr_reservation_list(self._make_http_request_read('LAN_lan.htm'))

    def push_addr_reservation_list(self, lst_new):
        lst_new.ensure_valid()

        lst_old = self.get_addr_reservation_list()

        if lst_old == lst_new:
            return True

        submit_token = lst_old.get_internal_param('submit_token')

        # delete all old (currently added) items first
        delete_url = 'lan.cgi' if submit_token is None else 'lan.cgi?id=%d' % submit_token
        for _ in lst_old:
            # delete from the front (id=0) as many times as needed
            data = {'Add': '', 'Edit': '', 'Delete': 'Delete', 'select': 0}
            self._make_http_request_write(delete_url, data)

        add_url = 'reserv.cgi' if submit_token is None else 'reserv.cgi?id=%d' % submit_token
        for id, item in enumerate(lst_new):
            data = _generate_addr_reservation_item_data(item)
            self._make_http_request_write(add_url, data)

        return self.get_addr_reservation_list() == lst_new

    @property
    def supports_reboot(self):
        return False

    def reboot(self):
        pass


class Netgear_WGR614v9(NetgearWGR614Base):

    def confirm_identity(self):
        return self._confirm_identity_meta_description('WGR614V9')

    def get_dmz_settings(self):
        return _parse_dmz_settings_WGR614v9(self._make_http_request_read('WAN_wan.htm'))

    def push_dmz_settings(self, settings):
        data = _generate_dmz_data_WGR614v9(settings)
        self._make_http_request_write('security.cgi', data)
        return True

    def get_wireless_settings(self):
        # Maps a security type with the document id, which contains its settings
        security_types_map = {'None': 3, 'WEP': 1, 'WPA-PSK': 2, 'WPA2-PSK': 2, 'WPA-AUTO-PSK': 2}

        html_initial = self._make_http_request_read('WLG_wireless.htm')
        match_object = re.compile('var secuType="(%s)";' % '|'.join(security_types_map)).search(html_initial)
        if match_object is None:
            raise RouterFetchError('Cannot parse initial wireless settings')
        doc_name = 'WLG_wireless%d.htm' % security_types_map[match_object.group(1)]

        args = [match_object.group(1)]
        args.append(self._make_http_request_read(doc_name))
        args.append(self._make_http_request_read('WLG_adv.htm'))

        return _parse_wireless_settings(*args)

    def push_wireless_settings(self, settings):
        submit_token = settings.get_internal_param('submit_token')

        data_basic = _generate_wireless_basic_settings_WGR614v9(settings)
        path_basic = 'wireless.cgi' if submit_token is None else 'wireless.cgi?id=%d' % submit_token
        self._make_http_request_write(path_basic, data_basic)

        data_advanced = _generate_wireless_advanced_settings_WGR614v9(settings)
        path_advanced = 'wlg_adv.cgi' if submit_token is None else 'wlg_adv.cgi?id=%d' % submit_token
        self._make_http_request_write(path_advanced, data_advanced)

        return self.get_wireless_settings() == settings


class Netgear_WGR614v8(Netgear_WGR614v9):

    def confirm_identity(self):
        return self._confirm_identity_meta_description('WGR614v8')

    def get_dmz_settings(self):
        return _parse_dmz_settings_WGR614v8(self._make_http_request_read('WAN_wan.htm'))

    def push_dmz_settings(self, settings):
        data = _generate_dmz_data_WGR614v8(settings)
        self._make_http_request_write('security.cgi', data)
        return True

    def push_wireless_settings(self, settings):
        data_basic = _generate_wireless_basic_settings_WGR614v9(settings)
        self._make_http_request_write('wireless.cgi', data_basic)

        data_advanced = _generate_wireless_advanced_settings_WGR614v8(settings)
        self._make_http_request_write('wlg_adv.cgi', data_advanced)

        return self.get_wireless_settings() == settings


class Netgear_WGR614v7(Netgear_WGR614v8):

    def confirm_identity(self):
        return self._confirm_identity_meta_description('WGR614v7')

    def push_dmz_settings(self, settings):
        data = _generate_dmz_data_WGR614v7(settings)
        self._make_http_request_write('security.cgi', data)
        return True

    def get_wireless_settings(self):
        html_initial = self._make_http_request_read('WLG_wireless.htm')

        match_object = re.compile('var authType="(.+?)";').search(html_initial)
        if match_object is None:
            raise RouterFetchError('Cannot parse initial wireless settings/authType')
        auth_type = match_object.group(1)

        match_object = re.compile('var wepStatus="(.+?)";').search(html_initial)
        if match_object is None:
            raise RouterFetchError('Cannot parse initial wireless settings/wepStatus')
        wep_status = match_object.group(1)

        if wep_status == 'Enable':
            if auth_type in ('WPA-PSK', 'WPA2-PSK', 'WPA-AUTO-PSK'):
                doc_name = 'WLG_wireless2.htm'
            else:
                auth_type = 'WEP' # I've seen auth_type='None' to mean 'WEP'.. weird..
                doc_name = 'WLG_wireless1.htm'
        else:
            doc_name = 'WLG_wireless3.htm'

        args = [auth_type]
        args.append(self._make_http_request_read(doc_name))
        args.append(self._make_http_request_read('WLG_adv.htm'))

        settings = _parse_wireless_settings(*args)
        # Only v7 doesn't support auto channel
        settings.set_auto_channel_support(False)

        return settings

    def push_wireless_settings(self, settings):
        # It's not really confirmed, but pushing advanced before basic looks better
        # because basic restarts the router shortly after it's being changed
        # i can't say the same about advanced though
        data_advanced = _generate_wireless_advanced_settings_WGR614v7(settings)
        data_basic = _generate_wireless_basic_settings_WGR614v9(settings)

        # Shortly after we push settings, the router reboots automatically
        # so the settings we try to push last may not make it,
        # especially if the connection is laggy
        self._make_http_request_write('wlg_adv.cgi', data_advanced)
        self._make_http_request_write('wireless.cgi', data_basic)

        # the router reboots automatically very soon
        # we can't make sure everything went fine..
        return True


def _parse_router_info(html):
    obj = RouterInfo()

    regex_hardware = re.compile('<b>Hardware Version</b>(?:.+?)>([a-zA-Z0-9]+)</td>', re.DOTALL)
    match_object = regex_hardware.search(html)
    if match_object is None:
        raise RouterParseError('Cannot parse hardware version')
    obj.set_hardware_version(match_object.group(1))

    regex_firmware = re.compile('<b>Firmware Version </b>(?:.+?)>([a-zA-Z0-9\s\.\(\)_]+)</td>', re.DOTALL)
    match_object = regex_firmware.search(html)
    if match_object is None:
        raise RouterParseError('Cannot parse firmware version')
    obj.set_firmware_version(match_object.group(1))

    return obj


def _parse_uptime_to_seconds(html):
    """Parses an uptime string such as ` 15 days 10:11:12` or `10:11:12` to seconds."""

    regex = re.compile('<!>(?: ([0-9]+) days? )?([0-9]+):([0-9]+):([0-9]+)<!>')
    match_object = regex.search(html)
    if match_object is None:
        raise RouterParseError('Cannot match uptime string')

    days, hours, minutes, seconds = map(lambda x: int(x) if x is not None else 0, match_object.groups())

    return days * 86400 + hours * 3600 + minutes * 60 + seconds


def _parse_traffic_stats(html):
    # Sadly, we can only get packets count information.. no size stats available

    regex = re.compile('WAN</span>(?:.+?)([0-9]+)</span>(?:.+?)([0-9]+)</span>', re.DOTALL)
    match_object = regex.search(html)
    if match_object is None:
        raise RouterParseError('Cannot find traffic stats information')

    packets_sent, packets_recv = map(int, match_object.groups())

    return TrafficStats(0, 0, packets_recv, packets_sent)


def _parse_pppoe_online_time(html):
    # <TD NOWRAP width="50%">23:05:47</td>
    # or
    # <TD NOWRAP width="50%"> 1 day 00:41:36</td>
    # or
    # <TD NOWRAP width="50%"> 10 days 00:41:36</td>

    regex = re.compile('<B>Connection Time</B>(?:.+?)>(?: ([0-9]+) days? )?([0-9]+):([0-9]+):([0-9]+)</td>', re.DOTALL)
    match_object = regex.search(html)
    if match_object is None:
        raise RouterParseError('Cannot parse online time information')

    days, hours, minutes, seconds = map(lambda x: int(x) if x is not None else 0, match_object.groups())

    return days * 86400 + hours * 3600 + minutes * 60 + seconds


def _parse_mac_address(html):
    regex = re.compile('Internet Port(?:.+?)MAC Address </b></td>(?:.+?)>(.+?)</td>', re.DOTALL)
    match_object = regex.search(html)
    if match_object is None:
        raise RouterParseError('Cannot parse MAC address information')

    return converter.normalize_mac(match_object.group(1))


def _parse_dns_servers(html):
    regex = re.compile('Domain Name Server <!><br></b></td>(?:.+?)>(.+?)</td>', re.DOTALL)
    match_object = regex.search(html)
    if match_object is None:
        raise RouterParseError('Cannot parse DNS servers information')

    ips = match_object.group(1) #<br> separated list of IPs
    return [ip for ip in ips.split('<br>') if validator.is_valid_ip_address(ip)]


def _parse_connected_clients_list(html):
    lst = ConnectedClientsList()

    regex = "<tr>(?:.+?)<span class=\"ttext\">(.+?)</span>(?:.+?)<span class=\"ttext\">(.+?)</span>(?:.+?)<span class=\"ttext\">(.+?)</span>(?:.+?)</tr>"

    for ip, name, mac in re.compile(regex, re.DOTALL).findall(html):
        if ip == '--':
            # I've seen such entries on WGR614v7 only.. let's ignore them
            continue

        if not validator.is_valid_ip_address(ip):
            raise RouterParseError('Invalid IP address: %s' % ip)

        item = ConnectedClientsListItem()
        item.set_client_name(name)
        item.set_mac(converter.normalize_mac(mac))
        item.set_ip(ip)
        item.set_lease_time(None) # no lease time information available

        lst.append(item)

    return lst


def _parse_dmz_settings_WGR614v9(html):
    match_object = re.compile("name=\"dmz_ip\" type=hidden value= \"(.+?)\">").search(html)
    if match_object is None:
        raise RouterParseError('Cannot parse DMZ IP')
    ip = match_object.group(1)
    if not validator.is_valid_ip_address(ip):
        raise RouterParseError('Invalid DMZ IP address: %s' % ip)


    match_object = re.compile("var dmzEnable = \"([0-1])\";").search(html)
    if match_object is None:
        raise RouterParseError('Cannot parse DMZ Enabled Status')
    is_enabled = True if int(match_object.group(1)) == 1 else False


    settings = DMZSettings()
    settings.set_supported_status(True)
    settings.set_ip(ip)
    settings.set_enabled_status(is_enabled)

    return settings


def _parse_dmz_settings_WGR614v8(html):
    match_object = re.compile('var lanIpAddr = "(.+?)";').search(html)
    if match_object is None:
        raise RouterParseError('Cannot parse DMZ IP')
    ip = match_object.group(1)
    if not validator.is_valid_ip_address(ip):
        raise RouterParseError('Invalid DMZ IP address: %s' % ip)


    match_object = re.compile("var dmzEnable = \"([0-1])\";").search(html)
    if match_object is None:
        raise RouterParseError('Cannot parse DMZ Enabled Status')
    is_enabled = True if int(match_object.group(1)) == 1 else False


    settings = DMZSettings()
    settings.set_supported_status(True)
    settings.set_ip(ip)
    settings.set_enabled_status(is_enabled)

    return settings

def __parse_wep_password(html_basic):
    regex = re.compile('<input type="text" name="KEY1" maxLength=32 size=34 value="(.+?)" onkeydown')
    match_object = regex.search(html_basic)
    if match_object is None:
        raise RouterParseError('Cannot determine WEP password')

    return match_object.group(1)

def _parse_wireless_settings(security_type, html_basic, html_advanced):
    settings = WirelessSettings()
    settings.add_security_support(WirelessSettings.SECURITY_TYPE_WEP64)
    settings.add_security_support(WirelessSettings.SECURITY_TYPE_WEP128)
    settings.add_security_support(WirelessSettings.SECURITY_TYPE_WPA)
    settings.add_security_support(WirelessSettings.SECURITY_TYPE_WPA2)
    settings.set_ascii_wep_password_support_status(False)
    settings.set_reboot_requirement_status(False)

    # Determine the submit token.. some WGR614v9 models have such a token
    # It's either some form of CSRF protection or something else..
    match_object = re.compile('<form method="POST" action="wireless.cgi\?id=([0-9]+)">').search(html_basic)
    if match_object is None:
        settings.set_internal_param('submit_token', None)
    else:
        settings.set_internal_param('submit_token', int(match_object.group(1)))

    if security_type == 'WEP':
        if '<option selected value="1">64bit</option>' in html_basic:
            settings.set_security_type(WirelessSettings.SECURITY_TYPE_WEP64)
        elif '<option selected value="2">128bit</option>' in html_basic:
            settings.set_security_type(WirelessSettings.SECURITY_TYPE_WEP128)
        else:
            raise RouterParseError('Cannot determine WEP key length')

        settings.set_password(__parse_wep_password(html_basic))
    elif security_type == 'WPA-PSK':
        settings.set_security_type(WirelessSettings.SECURITY_TYPE_WPA)
        # password extraction is done below
    elif security_type in ('WPA2-PSK', 'WPA-AUTO-PSK'):
        settings.set_security_type(WirelessSettings.SECURITY_TYPE_WPA2)
        # password extraction is done below
    else: # security_type = `Disable` or something else that we don't handle..
        settings.set_security_type(WirelessSettings.SECURITY_TYPE_NONE)
        settings.set_password('')

    if settings.security_type_is_wpa:
        regex = re.compile('<input type="text" name="passphrase" size=20 maxLength=64 value="(.+?)" onFocus')
        match_object = regex.search(html_basic)
        if match_object is None:
            raise RouterParseError('Cannot determine WPA password')
        password = match_object.group(1)
        if '*****' in password:
            # WGR614v7 doesn't present us with the real password, but substitutes it with * chars
            # that's not the case for v8 and v9 though
            password = None
        settings.set_password(password)

    regex = re.compile('<input type="text" name="ssid" value="(.+?)"')
    match_object = regex.search(html_basic)
    if match_object is None:
        raise RouterParseError('Cannot determine SSID')
    settings.set_ssid(match_object.group(1))


    regex = re.compile('<input type="hidden" name="initChannel" value="([0-9]+)">')
    match_object = regex.search(html_basic)
    if match_object is None:
        raise RouterParseError('Cannot determine channel')
    settings.set_channel(int(match_object.group(1)))


    if '<input type="checkbox"  checked name="enable_ap" value="enable_ap">' in html_advanced:
        is_enabled = True
    else:
        is_enabled = False
    settings.set_enabled_status(is_enabled)


    if '<input type="checkbox"  checked name="ssid_bc" value="ssid_bc">' in html_advanced:
        is_broadcasting = True
    else:
        is_broadcasting = False
    settings.set_ssid_broadcast_status(is_broadcasting)


    if '<input type="checkbox"  checked name="enable_wmm" value="enable_wmm">' in html_advanced:
        is_wmm_enabled = True
    else:
        is_wmm_enabled = False
    settings.set_internal_param('enable_wmm', is_wmm_enabled)


    regex = re.compile("Select Region(?:.+?)<option selected value=\"([0-9]+)\">")
    match_object = regex.search(html_basic)
    if match_object is None:
        raise RouterParseError('Cannot determine Region value')
    settings.set_internal_param('WRegion', int(match_object.group(1)))

    return settings


def _parse_addr_reservation_list(html):
    lst = DHCPReservationList()
    lst.set_reboot_requirement_status(False)

    # Determine the submit token.. some WGR614v9 models have such a token
    # It's either some form of CSRF protection or something else..
    match_object = re.compile('<form name="frmLan" method="POST" action="lan.cgi\?id=([0-9]+)">').search(html)
    if match_object is None:
        lst.set_internal_param('submit_token', None)
    else:
        lst.set_internal_param('submit_token', int(match_object.group(1)))

    regex = '<tr>(?:.+?)<span class="ttext">(.+?)</span></td>(?:.+?)<span class="ttext">(?:.+?)</span></td>(?:.+?)<span class="ttext">(.+?)</span></td></tr>'
    for ip, mac in re.compile(regex).findall(html):
        item = DHCPReservationListItem()
        item.set_ip(ip)
        item.set_mac(mac)
        lst.append(item)

    return lst


def _parse_dhcp_settings(html):
    settings = DHCPServerSettings()
    settings.set_enabled_status('<INPUT name=lan_proto type=hidden value= "dhcp">' in html)

    match_object = re.compile('<INPUT name=dhcp_start type=hidden value= "(.+?)"').search(html)
    if match_object is None:
        raise RouterParseError('Cannot determine DHCP start IP')
    settings.set_ip_start(match_object.group(1))

    match_object = re.compile('<INPUT name=dhcp_end type=hidden value= "(.+?)"').search(html)
    if match_object is None:
        raise RouterParseError('Cannot determine DHCP end IP')
    settings.set_ip_end(match_object.group(1))

    settings.ensure_valid()

    return settings


def _generate_dmz_data_WGR614v9(settings):
    settings.ensure_valid()

    data = {}
    data['rspToPing'] = 'rspToPing'
    data['wan_mtu'] = 1480
    data['NatInboundFiltering'] = 'Secured'
    data['apply'] = 'Apply'
    data['wan_way'] = 1492
    data['nat_inbound_filtering'] = 1
    data['wan_proto'] = 'pppoe'
    data['nvram_mtu'] = 1480
    data['dmz_ip'] = settings.ip

    if settings.is_enabled:
        data['dmz_enable'] = 'dmz_enable'

    data['dmzip1'], data['dmzip2'], data['dmzip3'], data['dmzip4'] = map(int, settings.ip.split('.'))

    return data


def _generate_dmz_data_WGR614v8(settings):
    data = _generate_dmz_data_WGR614v9(settings)
    del data['dmz_ip']
    return data


def _generate_dmz_data_WGR614v7(settings):
    data = _generate_dmz_data_WGR614v8(settings)

    # Connect Automatically, as Required
    data['dod'] = 'dod'

    return data


def _generate_wireless_basic_settings_WGR614v9(settings):
    settings.ensure_valid()

    data = {}
    data['ssid'] = settings.ssid
    data['WRegion'] = settings.get_internal_param('WRegion')
    data['w_channel'] = settings.channel
    data['opmode'] = 'g and b'
    data['Apply'] = 'Apply'
    data['initChannel'] = 0 # some hidden field
    data['wds_enable'] = 0
    data['tempSetting'] = 0
    data['tempRegion'] = settings.get_internal_param('WRegion')

    if settings.security_type_is_wep:
        data['security_type'] = 'WEP'
        data['authAlgm'] = 'automatic'
        data['initAuthType'] = 'automatic'
        data['initDefaultKey'] = 0
        data['wepenc'] = 1 if settings.security_type == settings.__class__.SECURITY_TYPE_WEP64 else 2
        data['wep_key_no'] = 1 # the id of the WEP key to use (between 1 and 4)
        data['KEY1'] = settings.password
        data['KEY2'] = ''
        data['KEY3'] = ''
        data['KEY4'] = ''
        data['passphraseStr'] = '' # This is a temporary field used in the UI only
    elif settings.security_type_is_wpa:
        data['security_type'] = 'WPA-PSK' if settings.security_type == settings.__class__.SECURITY_TYPE_WPA else 'WPA2-PSK'
        data['passphrase'] = settings.password
        data['pfChanged'] = 1 # i don't know what this does
        data['tempSetting'] = 1 # i don't know what this does
    else:
        data['security_type'] = 'Disable'
        data['tempSetting'] = 1 # i don't know what this does

    return data


def _generate_wireless_advanced_settings_WGR614v9(settings):
    settings.ensure_valid()

    data = {}
    data['frag'] = 2346
    data['rts'] = 2347
    data['enable_shortpreamble'] = '' # empty means 'enable long preamble'
    data['Apply'] = 'Apply'
    data['enable_wmm'] = 'enable_wmm'

    if settings.is_enabled:
        data['enable_ap'] = 'enable_ap'

    if settings.is_broadcasting_ssid:
        data['ssid_bc'] = 'ssid_bc'

    return data


def _generate_wireless_advanced_settings_WGR614v8(settings):
    data = _generate_wireless_advanced_settings_WGR614v9(settings)
    data['wsc_config'] = 'on'
    data['wps_enable'] = 'enabled'
    return data


def _generate_wireless_advanced_settings_WGR614v7(settings):
    settings.ensure_valid()

    data = {}
    data['Apply'] = 'Apply'
    data['enable_wmm'] = 1

    if settings.is_enabled:
        data['enable_ap'] = 'enable_ap'

    if settings.is_broadcasting_ssid:
        data['ssid_bc'] = 'ssid_bc'

    return data


def _generate_addr_reservation_item_data(item):
    ip_parts = item.ip.split('.')

    data = {}
    data['apply'] = 'Add'
    data['dv_name'] = item.mac # device name, up to 20 chars
    data['rsv_ip'] = item.ip
    data['rsv_ip1'] = ip_parts[0]
    data['rsv_ip2'] = ip_parts[1]
    data['rsv_ip3'] = ip_parts[2]
    data['rsv_ip4'] = ip_parts[3]
    data['rsv_mac'] = item.mac.upper()
    data['rsv_mode'] = 'add'

    return data
