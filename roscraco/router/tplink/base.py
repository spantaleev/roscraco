import re
import ast
import base64
import urllib

from roscraco.router.base import RouterBase

from roscraco.helper import validator, converter, split_in_groups
from roscraco.exception import RouterParseError, RouterIdentityError, \
     RouterError

from roscraco.response import RouterInfo, TrafficStats, DMZSettings, \
     ConnectedClientsListItem, ConnectedClientsList, \
     DHCPReservationList, DHCPReservationListItem, DHCPServerSettings


class TplinkBase(RouterBase):

    def _perform_http_request(self, *args, **kwargs):
        # Without the Accept-Encoding header the web-interface of the
        # WR941N router (and potentially some other models) crashes.
        # A bug report was submitted to TpLink, but still no progress.
        # Even if they fix it, thousands of routers out there would still
        # run the old firmware and break.
        auth = base64.b64encode('%s:%s' % (self.username, self.password))
        kwargs['headers'] = [
            ('Accept-Encoding', 'gzip,deflate'),
            ('Authorization', 'Basic %s' % auth),
        ]
        return RouterBase._perform_http_request(self, *args, **kwargs)

    def _get_status_array(self, array_name):
        contents = self._make_http_request_read('StatusRpm.htm')
        return _extract_js_array_data(contents, array_name)

    def get_router_info(self):
        return _parse_router_info(self._get_status_array('statusPara'))

    def get_mac_address(self):
        return _parse_mac_address(self._get_status_array('wanPara'))

    def get_dns_servers(self):
        return _parse_dns_servers(self._get_status_array('wanPara'))

    def get_pppoe_online_time(self):
        return _parse_pppoe_online_time(self._get_status_array('wanPara'))

    def get_uptime(self):
        return _parse_uptime(self._get_status_array('statusPara'))

    def get_traffic_stats(self):
        return _parse_traffic_stats(self._get_status_array('statistList'))

    def get_connected_clients_list(self):
        return _parse_connected_clients_list(self._make_http_request_read('AssignedIpAddrListRpm.htm'))

    def get_dmz_settings(self):
        return _parse_dmz_settings(self._make_http_request_read('DMZRpm.htm'))

    def push_dmz_settings(self, settings):
        get_params = _generate_dmz_data(settings)
        contents = self._make_http_request_write('DMZRpm.htm?%s' % urllib.urlencode(get_params))
        return _parse_dmz_settings(contents) == settings

    def get_addr_reservation_list(self):
        return _parse_addr_reservation_list(self._make_http_request_read('FixMapCfgRpm.htm'))

    def push_addr_reservation_list(self, lst_new):
        lst_new.ensure_valid()

        lst_old = self.get_addr_reservation_list()
        if lst_old == lst_new:
            return True

        # delete all old (currently added) items first
        for _ in lst_old:
            # delete from the front (id=0) as many times as needed
            self._make_http_request_write('FixMapCfgRpm.htm?Del=0')

        for item in lst_new:
            data = _generate_addr_reservation_item_data(item)
            contents = self._make_http_request_write('FixMapCfgRpm.htm?%s' % urllib.urlencode(data))

            if 'var errCode = "' in contents:
                # could be several things (1. already added; 2. invalid MAC (broadcast..); ..)
                raise RouterError('Error while pushing %s/%s' % (item.ip, item.mac))

        return self.get_addr_reservation_list() == lst_new

    def get_dhcp_settings(self):
        return _parse_dhcp_settings(self._make_http_request_read('LanDhcpServerRpm.htm'))

    @property
    def supports_reboot(self):
        return True

    def reboot(self):
        self._make_http_request_write('SysRebootRpm.htm?Reboot=Reboot')

    @property
    def url_base(self):
        return 'http://%s:%d/userRpm/' % (self.host, self.port)

    def _ensure_www_auth_header(self, header_value_expected):
        info = self._perform_http_request('%sStatusRpm.htm' % self.url_base)[1]
        header_auth = info.getheader('WWW-Authenticate')
        if header_auth != header_value_expected:
            raise RouterIdentityError(
                'Bad or missing WWW-Authenticate header: %s/%s' %
                    (header_auth, header_value_expected)
            )

def is_valid_mac_address(mac):
    """Validates a MAC address in the format that TPLink routers expects."""
    regex = re.compile('(([a-fA-F0-9]{2}-){5})([a-fA-F0-9]{2})$')
    return regex.match(mac) is not None


def _extract_js_array_data(contents, array_name):
    """Extracts the contents of a javascript array on the page.

    The TP-Link control panel often uses javascript arrays to store some
    of the data on the page that would later be used to generate the UI.

    Here's an example of an array full of data:

    var statistList = new Array(
    14131821, 1757256, 16065, 12432,
    0,0 );

    What we're actually doing below is:
    1) Find where the real array data starts (after the `(` char)
    2) Find where the real array data ends (after `);`)
    3) Safely parse the array data `(..)` as a tuple
    """
    try:
        find = 'var %s = new Array(' % array_name
        start = contents.index(find) + find.__len__()
        end = contents.index(');', start)
        array_contents = '(%s)' % contents[start:end]

        result = ast.literal_eval(array_contents)
        if not isinstance(result, tuple):
            raise RouterParseError('Bad javascript array evaluation. Result not a tuple!')
        # ast.literal_eval may mess up our nice unicode strings
        # depending on the default system encoding (usually ascii)
        result = tuple([v.decode('utf-8', 'ignore')
                        if isinstance(v, bytes) else v for v in result])
        return result
    except Exception, e:
        raise RouterParseError('Failed at evaluating array %s: %s' % (array_name, repr(e)))


def _parse_pppoe_online_time(data_array):
    try:
        uptime_string = data_array[12] # `0 day(s) 10:11:12`

        # non-pppoe routers have a different array format.. no uptime there
        if uptime_string == '':
            return None

        return _parse_uptime_to_seconds(uptime_string)
    except IndexError, e:
        raise RouterParseError('Cannot access the array index: %s' % repr(e))


def _parse_uptime_to_seconds(string):
    """Parses an uptime string such as `0 day(s) 10:11:12`
    or `0 days 10:18:45` to seconds.

    These 2 strings both appear in the router interface.
    """
    regex = re.compile('([0-9]+) (?:days|day\(s\)) ([0-9]+):([0-9]+):([0-9]+)')
    match_object = regex.match(string)
    if match_object is None:
        raise RouterParseError('Invalid uptime string `%s`' % str(string))

    days, hours, minutes, seconds = map(int, match_object.groups())
    return days * 86400 + hours * 3600 + minutes * 60 + seconds


def _parse_uptime(data_array):
    try:
        return int(data_array[4])
    except IndexError, e:
        raise RouterParseError('Cannot access the array index: %s' % repr(e))


def _parse_router_info(data_array):
    try:
        obj = RouterInfo()
        obj.set_hardware_version(data_array[6])
        obj.set_firmware_version(data_array[5])

        return obj
    except IndexError, e:
        raise RouterParseError('Cannot access the array index: %s' % repr(e))


def _parse_mac_address(data_array):
    try:
        return converter.normalize_mac(data_array[1])
    except IndexError, e:
        raise RouterParseError('Cannot access the array index: %s' % repr(e))


def _parse_dns_servers(data_array):
    try:
        dns_ips = data_array[11].split(' , ')
        return [ip.strip(' ') for ip in dns_ips if validator.is_valid_ip_address(ip)]
    except IndexError, e:
        raise RouterParseError('Cannot access the array index: %s' % repr(e))


def _parse_traffic_stats(data_array):
    data_array = data_array[:4]
    if len(data_array) != 4:
        raise RouterParseError('Unexpected stats size: %d' % len(data_array))

    data_array = map(int, list(data_array))
    return TrafficStats(*data_array)


def _parse_lease_time(string):
    """Parses a lease time string such as `04:23:15` to seconds.

    The format is HH:MM:SS
    """
    parts = string.split(':')
    if len(parts) != 3:
        raise RouterParseError('Cannot parse lease time string: %s' % string)

    try:
        parts = map(int, parts)
    except ValueError, e:
        raise RouterParseError('Found non-numeric part in lease time %s: %s' % (string, repr(e)))

    hours, minutes, seconds = parts

    return hours * 3600 + minutes * 60 + seconds


def _parse_dmz_settings(contents):
    array_name = 'DMZInf'

    result = _extract_js_array_data(contents, array_name)

    try:
        ip = result[1].strip(' ')
        if not validator.is_valid_ip_address(ip):
            raise RouterParseError('Invalid IP address: %s' % ip)

        obj = DMZSettings()
        obj.set_supported_status(True)
        obj.set_enabled_status(result[0] == 1)
        obj.set_ip(result[1])

        return obj
    except IndexError, e:
        raise RouterParseError(repr(e))


def _parse_addr_reservation_list(contents):
    array_name = 'dhcpList'

    result = _extract_js_array_data(contents, array_name)
    result = result[:-2]    # the last 2 elements are not needed

    # each 3 subsequent items are related (mac_address, ip, is_enabled)
    list_raw = split_in_groups(result, 3)

    reservation_list = DHCPReservationList()
    for mac, ip, is_enabled in list_raw:
        item = DHCPReservationListItem()
        item.set_mac(converter.normalize_mac(mac))
        item.set_ip(ip)
        item.set_enabled_status(is_enabled == 1)
        reservation_list.append(item)

    return reservation_list


def _parse_connected_clients_list(html):
    # the last 2 elements of the data array are not needed
    result = _extract_js_array_data(html, 'DHCPDynList')[:-2]

    lst = ConnectedClientsList()

    # each 4 subsequent items are related (client_name, mac_address, ip, lease_time)
    for client_name, mac, ip, lease_time in split_in_groups(result, 4):
        if not validator.is_valid_ip_address(ip):
            raise RouterParseError('Invalid IP address: %s' % ip)

        item = ConnectedClientsListItem()
        item.set_client_name(client_name)
        item.set_mac(converter.normalize_mac(mac))
        item.set_ip(ip)

        if lease_time == 'Permanent':
            item.set_lease_time(item.__class__.LEASE_TIME_PERMANENT)
        else:
            item.set_lease_time(_parse_lease_time(lease_time))

        lst.append(item)

    return lst


def _parse_dhcp_settings(html):
    settings = DHCPServerSettings()

    array = _extract_js_array_data(html, 'DHCPPara')

    try:
        settings.set_enabled_status(int(array[0]) == 1)
        settings.set_ip_start(array[1])
        settings.set_ip_end(array[2])
    except IndexError, e:
        raise RouterParseError(repr(e))

    settings.ensure_valid()
    return settings


def _generate_dmz_data(settings):
    settings.ensure_valid()

    get_params = {}
    get_params['ipAddr'] = settings.ip
    get_params['enable'] = 1 if settings.is_enabled else 0
    get_params['netMask'] = '255.255.255.0'
    get_params['Save'] = 'Save'
    return get_params


def _denormalize_mac(mac):
    """Takes a normalized mac address (all lowercase hex, no separators)
    and converts it to the TpLink format.

    Example::
        _denormalize_mac('abcdef123456') == 'ab-cd-ef-12-34-56'
    """
    return '-'.join((mac[i] + mac[i+1] for i in range(0, 12, 2)))


def _generate_addr_reservation_item_data(item):
    data = {}
    data['Mac'] = _denormalize_mac(item.mac)
    data['Ip'] = item.ip
    data['State'] = 1 if item.is_enabled else 0
    data['Changed'] = 0
    data['SelIndex'] = 0
    data['Page'] = 1
    data['Save'] = 'Save'
    return data
