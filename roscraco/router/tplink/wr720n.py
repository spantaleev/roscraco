from wr740n import Tplink_WR740N


class Tplink_WR720N(Tplink_WR740N):

    def confirm_identity(self):
        self._ensure_www_auth_header('Basic realm="150Mbps Wireless N Router TL-WR720N"')
