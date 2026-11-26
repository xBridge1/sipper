"""Small text helpers shared by the parsers."""


def is_ascii_digits(value):
    """True for non-empty ASCII digit strings.

    ``str.isdigit`` also accepts characters such as "\u00b2" that ``int()``
    rejects, which let a single Latin-1 byte crash the SIP parser.
    """
    return bool(value) and value.isascii() and value.isdigit()
