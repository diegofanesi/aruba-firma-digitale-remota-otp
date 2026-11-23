"""Errors carrying an Italian message ready to show to the user."""

from __future__ import annotations


class FirmaError(Exception):
    """Base error. `message` is user-facing Italian text; `detail` is optional technical context."""

    exit_code = 1

    def __init__(self, message: str, *, detail: str | None = None):
        super().__init__(message)
        self.message = message
        self.detail = detail


class CredentialsError(FirmaError):
    """Wrong or missing username, domain or password."""

    exit_code = 3


class OtpError(FirmaError):
    """OTP refused (wrong, expired, or the account is blocked: ARSS can't tell which)."""

    exit_code = 3


class SessionExpired(FirmaError):
    """The signing session ended before the batch was finished."""


class ServiceError(FirmaError):
    """ARSS answered with an error we don't map more precisely."""

    def __init__(self, message: str, *, code: str | None = None, detail: str | None = None):
        super().__init__(message, detail=detail)
        self.code = code


class NetworkError(FirmaError):
    """The Aruba service could not be reached."""


class FileError(FirmaError):
    """A local file can't be read, parsed or written."""
