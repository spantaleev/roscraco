from wr740n import Tplink_WR740N


class Tplink_WR941N(Tplink_WR740N):

    def confirm_identity(self):
        self._ensure_www_auth_header('Basic realm="TP-LINK Wireless N Router WR941N"')
