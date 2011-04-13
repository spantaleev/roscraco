from wr740n import Tplink_WR740N


class Tplink_WR741N(Tplink_WR740N):

    def confirm_identity(self):
        self._ensure_www_auth_header('Basic realm="TP-LINK Wireless Lite N Router WR741N"')

