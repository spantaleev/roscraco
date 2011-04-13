from wr740n import Tplink_WR740N


class Tplink_WR940N(Tplink_WR740N):

    def confirm_identity(self):
        self._ensure_www_auth_header('Basic realm="TP-LINK Wireless N Router WR940N"')
