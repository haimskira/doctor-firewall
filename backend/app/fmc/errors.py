"""FMC client errors. ``code`` is safe to return to API clients; messages are for logs."""

from __future__ import annotations


class FmcError(Exception):
    code = "fmc_error"


class FmcTlsError(FmcError):
    code = "tls_error"


class FmcAuthError(FmcError):
    code = "auth_failed"


class FmcUnavailableError(FmcError):
    code = "unreachable"


class FmcRateLimitedError(FmcError):
    code = "rate_limited"


class FmcProtocolError(FmcError):
    """The FMC answered with something that does not match the documented contract."""

    code = "unexpected_response"
