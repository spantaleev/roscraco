from __future__ import division

def print_info(router_obj):
    print('Details for router at %s:%d' % (router_obj.host, router_obj.port))
    print('')

    router_info = router_obj.get_router_info()
    print('Router %s %s running on firmware %s' % (router_obj.__class__.__name__, router_info.hardware_version, router_info.firmware_version))
    print('')

    uptime = router_obj.get_uptime()
    if uptime is None:
        print('Router uptime: UNKNOWN')
    else:
        print('Router uptime: %d seconds (~%d hours)' % (uptime, uptime / 3600))

    online_time = router_obj.get_pppoe_online_time()
    if online_time is None:
        print('Router online time: UNKNOWN')
    else:
        print('Router online time: %d seconds (~%d hours)' % (online_time, online_time / 3600))

    print('')

    stats = router_obj.get_traffic_stats()
    print('Traffic statistics:')
    print(' - Received %.2fMB (%d packets)' % (stats.bytes_recv / 1024 / 1024, stats.packets_recv))
    print(' - Sent %.2fMB (%d packets)' % (stats.bytes_sent / 1024 / 1024, stats.packets_sent))
    print('')


    print('Router MAC address: %s' % router_obj.get_mac_address())
    print('')

    print ('DNS servers: %s' % ', '.join(router_obj.get_dns_servers()))
    print('')


    connected_clients_list = router_obj.get_connected_clients_list()
    print('Connected: %d clients' % len(connected_clients_list))
    for item in connected_clients_list:
        name, mac, ip = item.client_name, item.mac, item.ip

        if item.lease_time is None:
            lease_info = ' [unknown lease time]'
        else:
            lease_info = '[PERMANENT]' if item.is_permanent_lease else ' - lease expires in %d seconds' % item.lease_time

        print(' - %s (%s / %s) %s' % (name, ip, mac, lease_info))
    print('')

    dmz_settings = router_obj.get_dmz_settings()
    if dmz_settings.is_supported:
        if dmz_settings.is_enabled:
            print('DMZ is active for %s' % dmz_settings.ip)
            dhcp_reservations = router_obj.get_addr_reservation_list()
            if not dhcp_reservations.has_ip(dmz_settings.ip):
                print(' - WARNING: no address reservation for the DMZ IP. This MAY be a problem')
            else:
                print(' - OK: %s is also in the address reservation list' % dmz_settings.ip)
        else:
            print('DMZ is disabled')
    else:
        print('DMZ is not supported')
    print('')


    dhcp_server = router_obj.get_dhcp_settings()
    if dhcp_server.is_enabled:
        print('DHCP server enabled with range %s - %s' % (dhcp_server.ip_start, dhcp_server.ip_end))
    else:
        print('DHCP server is disabled')


    reservation_list = router_obj.get_addr_reservation_list()
    if reservation_list.supports_reservations:
        print('DHCP address reservation list: %d addresses' % len(reservation_list))
        for item in reservation_list:
            mac, ip, is_enabled = item.mac, item.ip, item.is_enabled
            disabled_modifier = '' if is_enabled else '[DISABLED]'

            print(' - %s (%s) %s' % (ip, mac, disabled_modifier))
    else:
        print('Address reservations not supported')
    print('')


    wireless = router_obj.get_wireless_settings()
    if wireless.is_supported:
        print('Wireless settings:')
        if wireless.is_enabled:
            print(' - Wireless enabled')
        else:
            print(' - Wireless is supported, but DISABLED')

        ssid_modifier = '[public broadcast]' if wireless.is_broadcasting_ssid else '[PRIVATE broadcast]'
        print(' - SSID: %s %s' % (wireless.ssid, ssid_modifier))

        security_modifier = ''
        if wireless.security_type_is_wep and wireless.password is not None:
            security_modifier = '/HEX' if wireless.is_wep_password_in_hex else '/ASCII'
        print(' - Security: %s%s' % (wireless.security_type.upper(), security_modifier))

        if wireless.channel is None:
            print(' - Channel: <UNKNOWN>')
        else:
            print(' - Channel: %d' % wireless.channel)

        if wireless.password is None:
            print(' - Password: <UNKNOWN>')
        else:
            print(' - Password: %s' % wireless.password)
    else:
        print('Wireless is not supported!')
    print('')


def split_in_groups(item, group_size):
    """Splits an iterable in groups of tuples.

    If we take an incoming list/tuple like: ('id1', 'val1', 'id2', 'val2')
    and split it with group_size 2, we'll get: [('id1', 'val1'), ('id2', 'val2')]

    If we take a string like: 'abcdef'
    and split it with group_size 2, we'll get: ['ab', 'cd', 'ef']
    """
    return [item[idx_start:idx_start + group_size]
                for idx_start in range(0, len(item), group_size)]
