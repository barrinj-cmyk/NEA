import csv

import pytest

from whitelist import (
    WhitelistError,
    is_whitelisted,
    load_whitelist,
    validate_target,
)


def test_load_whitelist(tmp_path):
    path = tmp_path / "whitelist.csv"
    path.write_text("network\n10.0.4.0/24\n10.0.5.0/24\n", encoding="utf-8")
    networks = load_whitelist(path)
    assert [str(network) for network in networks] == ["10.0.4.0/24", "10.0.5.0/24"]


def test_load_whitelist_skips_blank_and_comment_rows(tmp_path):
    path = tmp_path / "whitelist.csv"
    path.write_text("network\n\n# lab networks\n10.0.4.0/24\n", encoding="utf-8")
    assert [str(n) for n in load_whitelist(path)] == ["10.0.4.0/24"]


@pytest.mark.parametrize("content", [
    "network\n",
    "network\nnot-a-network\n",
])
def test_load_whitelist_empty_or_malformed(tmp_path, content):
    path = tmp_path / "whitelist.csv"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(WhitelistError):
        load_whitelist(path)


def test_load_whitelist_rejects_public_or_narrow_range(tmp_path):
    public = tmp_path / "public.csv"
    public.write_text("network\n8.8.8.0/24\n", encoding="utf-8")
    with pytest.raises(WhitelistError):
        load_whitelist(public)

    narrow = tmp_path / "narrow.csv"
    narrow.write_text("network\n10.0.0.0/15\n", encoding="utf-8")
    with pytest.raises(WhitelistError):
        load_whitelist(narrow)


def test_load_whitelist_missing_file(tmp_path):
    with pytest.raises(WhitelistError, match="Cannot load whitelist"):
        load_whitelist(tmp_path / "missing.csv")


def test_is_whitelisted_accepts_host_or_subnet():
    from ipaddress import ip_network
    allowed = [ip_network("10.0.4.0/24")]
    assert is_whitelisted("10.0.4.25", allowed)
    assert is_whitelisted("10.0.4.0/25", allowed)
    assert not is_whitelisted("10.0.5.25", allowed)


@pytest.mark.parametrize("target", ["", "not-an-ip", None])
def test_is_whitelisted_rejects_invalid_target(target):
    from ipaddress import ip_network
    assert not is_whitelisted(target, [ip_network("10.0.4.0/24")])


def test_validate_target_returns_normalised_network():
    from ipaddress import ip_network
    allowed = [ip_network("10.0.4.0/24")]
    assert str(validate_target("10.0.4.99", allowed)) == "10.0.4.99/32"


def test_validate_target_rejects_outside_whitelist():
    from ipaddress import ip_network
    allowed = [ip_network("10.0.4.0/24")]
    with pytest.raises(WhitelistError, match="not in the whitelist"):
        validate_target("10.0.5.1", allowed)
