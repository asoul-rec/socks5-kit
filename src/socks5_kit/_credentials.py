"""Shared validation for optional per-connection SOCKS5 credentials."""


def validate_credentials(credentials: object) -> tuple[str, str] | None:
    """Validate eagerly, without including credential values in exceptions.

    Empty usernames/passwords are deliberately supported, matching the server's
    metadata handling. Lengths are measured in UTF-8 bytes, as on the wire.
    """
    if credentials is None:
        return None
    if not isinstance(credentials, tuple) or len(credentials) != 2:
        raise TypeError("credentials must be a (username, password) tuple or None")
    username, password = credentials
    if not isinstance(username, str) or not isinstance(password, str):
        raise TypeError("username and password must be strings")
    for value in (username, password):
        try:
            encoded = value.encode("utf-8")
        except UnicodeError:
            raise ValueError("credentials must contain valid UTF-8 text") from None
        if len(encoded) > 255:
            raise ValueError("username and password must each fit in 255 UTF-8 bytes")
    return username, password
