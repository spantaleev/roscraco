import urllib

from roscraco.response import WirelessSettings
from base import TplinkBase, _extract_js_array_data
from roscraco.exception import RouterFetchError

from wr740n import Tplink_WR740N


# Tp-Link WR340G v4 devices seem to be managed just like WR740N devices.
class Tplink_WR340Gv4(Tplink_WR740N):
    def confirm_identity(self):
        self._ensure_www_auth_header('Basic realm="TP-LINK Wireless G Router WR340G"')


class Tplink_WR340G(TplinkBase):

    def get_wireless_settings(self):
        html_settings = self._make_http_request_read('WlanNetworkRpm.htm')
        return _parse_wireless_settings_WR340G(html_settings)

    def push_wireless_settings(self, settings):
        get_params_settings = _generate_wireless_settings_data(settings)
        uri = 'WlanNetworkRpm.htm?%s' % urllib.urlencode(get_params_settings)
        try:
            contents = self._make_http_request_write(uri)
            # Settings are successfully pushed and the router will
            # start the rebooting process if we find this string.
            return 'Please wait a moment' in contents
        except RouterFetchError, e:
            # It sometimes updates the settings and
            # starts rebooting without sending a response correctly.
            # Try to detect that timeout and consider it a success too,
            # even though it may be caused by other reasons.
            if 'timed out' in str(e):
                return True
            raise

    def confirm_identity(self):
        self._ensure_www_auth_header('Basic realm="TP-LINK Wireless Router WR340G"')


def _parse_wireless_settings_WR340G(html_settings):
    """Extracts the Wireless settings from the page contents for a WR340G router."""

    obj = WirelessSettings()
    obj.add_security_support(WirelessSettings.SECURITY_TYPE_WEP64)
    obj.add_security_support(WirelessSettings.SECURITY_TYPE_WEP128)
    obj.add_security_support(WirelessSettings.SECURITY_TYPE_WPA)
    obj.add_security_support(WirelessSettings.SECURITY_TYPE_WPA2)

    settings_array = _extract_js_array_data(html_settings, 'wlanPara')
    wlan_list_array = _extract_js_array_data(html_settings, 'wlanList')

    security_type = int(settings_array[18])
    if security_type == 1: # WEP of some sort
        bit_length = int(wlan_list_array[1])
        if bit_length == 13: # 128 bit length
            security_type = WirelessSettings.SECURITY_TYPE_WEP128
        else:
            security_type = WirelessSettings.SECURITY_TYPE_WEP64
    elif security_type == 3: # WPA-PSK (WPA or WPA2)
        # string like '331', '332', '333'
        # we're interested in the 3rd char, which deals with WPA-PSK/WPA2-PSK
        # 3rd char possible values {1: WPA, 2: WPA2, 3: Automatic (WPA + WPA2)}
        security_options = settings_array[19]

        if int(security_options[2]) == 1:
            security_type = WirelessSettings.SECURITY_TYPE_WPA
        else:
            security_type = WirelessSettings.SECURITY_TYPE_WPA2
    else: # type is either 0 (no security) or 2 (WPA-Enterprise)
        security_type = WirelessSettings.SECURITY_TYPE_NONE
    obj.set_security_type(security_type)

    password = wlan_list_array[0] if obj.security_type_is_wep else settings_array[26]
    obj.set_password(password)

    obj.set_ssid(settings_array[2])
    obj.set_enabled_status(settings_array[8] != 0)
    obj.set_ssid_broadcast_status(settings_array[9] == 1)
    # We don't need to reboot manually..
    # The router reboots by itself when settings are pushed.
    obj.set_reboot_requirement_status(False)
    obj.set_channel(settings_array[6])
    obj.set_internal_param('region', settings_array[4])
    obj.set_internal_param('mode', settings_array[7])

    return obj


def _generate_wireless_settings_data(settings):
    """Generates a wireless settings data array to push to
    the router from the given wireless settings."""

    WirelessSettings = settings.__class__

    settings.ensure_valid()

    data = {}
    data['ssid'] = settings.ssid
    data['channel'] = settings.channel
    data['Save'] = 'Save'

    # preserve some of the params we don't handle
    for k in ('region', 'mode'):
        data[k] = settings.get_internal_param(k)

    if settings.is_enabled:
        data['ap'] = 2 # stands for Active/True

    if settings.is_broadcasting_ssid:
        data['broadcast'] = 2 # stands for Active/True

    if settings.security_type_is_wep:
        data['secType'] = 1
        data['secOpt'] = 3 # Security Option = Automatic
        data['keynum'] = 1 # which of the 4 WEP keys to use (if WEP is enabled)

        # These are the 4 WEP keys and their lengths.. empty by default - to be filled later if needed
        # only one of these keys is actively used (specified by `keynum` above)
        merge_with =  {'key2': '', 'key3': '', 'key4': '', 'length2': 0, 'length3': 0, 'length4': 0}
        data = dict(data, **merge_with)

        # 64bit = 5, 128bit = 13
        bit_length = 5 if settings.security_type == WirelessSettings.SECURITY_TYPE_WEP64 else 13

        data['key1'] = settings.password
        data['length1'] = bit_length
        data['keytype'] = 1 if settings.is_wep_password_in_hex else 2 # ASCII or HEX
    elif settings.security_type_is_wpa:
        data['secType'] = 3
        data['encrptType'] = 1 # Automatic encryption
        data['interval'] = 0 # group update interval
        data['pskSecret'] = settings.password

        if settings.security_type == WirelessSettings.SECURITY_TYPE_WPA:
            data['secOpt'] = 1 # WPA-PSK
        else:
            data['secOpt'] = 2 #WPA2-PSK
    else:
        # security is being disabled
        data['secType'] = 1

        # it's as if we're disabling it while on the WEP settings page..
        # let's send some of the WEP fields

        data['keytype'] = 1

        merge_with =  {'key1': '', 'key2': '', 'key3': '', 'key4': '', 'length1': 0, 'length2': 0, 'length3': 0, 'length4': 0}
        data = dict(data, **merge_with)

    # secStatus != 2 means 'disable security'
    if settings.security_type != WirelessSettings.SECURITY_TYPE_NONE:
        data['secStatus'] = 2 # stands for Active/True

    return data
