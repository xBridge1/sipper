from ciper.resources import resource_path


DEFAULT_VERSION = "1.0.1"


def installed_version():
    try:
        return resource_path("version.txt").read_text(encoding="ascii").strip() or DEFAULT_VERSION
    except OSError:
        return DEFAULT_VERSION
