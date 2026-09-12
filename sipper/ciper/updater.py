import json
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from packaging.version import InvalidVersion, Version
from ciper.version import installed_version


CURRENT_VERSION = installed_version()
REPOSITORY = "xBridge1/sipper"
LATEST_RELEASE_URL = f"https://api.github.com/repos/{REPOSITORY}/releases/latest"


@dataclass(frozen=True)
class UpdateInfo:
    version: str
    download_url: str
    release_url: str


def check_for_update(current_version=CURRENT_VERSION, timeout=3):
    try:
        request = Request(
            LATEST_RELEASE_URL,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "SIPPER-Update-Check",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        with urlopen(request, timeout=timeout) as response:
            release = json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, OSError, ValueError, json.JSONDecodeError):
        return None

    latest_version = _parse_version(release.get("tag_name", ""))
    installed_version = _parse_version(current_version)
    if latest_version is None or installed_version is None or latest_version <= installed_version:
        return None

    release_url = release.get("html_url", "")
    installer_url = next(
        (
            asset.get("browser_download_url", "")
            for asset in release.get("assets", [])
            if asset.get("name", "").startswith("SIPPER-Setup-")
            and asset.get("name", "").endswith(".exe")
        ),
        release_url,
    )
    if not installer_url:
        return None

    return UpdateInfo(
        version=str(latest_version),
        download_url=installer_url,
        release_url=release_url,
    )


def _parse_version(value):
    try:
        return Version(value.removeprefix("v"))
    except InvalidVersion:
        return None
