class RouterError(Exception):
    pass

class RouterFetchError(RouterError):
    pass

class RouterParseError(RouterError):
    pass

class RouterLoginError(RouterError):
    pass

class RouterSettingsError(RouterError):
    pass

class RouterIdentityError(RouterError):
    pass

class RouterNotSupported(RouterError):
    pass
