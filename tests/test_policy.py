from dataclasses import replace

import pytest
from app.config import get_settings
from app.policy import PolicyDenied, allowed_ip, validate_repo_target, validate_web_target


def test_web_target_safety():
    config=get_settings()
    for target in ['http://example.org','https://localhost','https://127.0.0.1','https://example.org/x',
                   'https://user:password@example.org','https://example.org:1234','https://example.org?a=b']:
        with pytest.raises(PolicyDenied):
            validate_web_target(target, config, resolve=False) if '127.0.0.1' not in target else validate_web_target(target, config,resolve=True)


def test_private_addresses_restricted():
    config=get_settings()
    for ip in ['127.0.0.1','169.254.169.254','10.0.0.1','172.16.0.2','192.168.0.1','::1']:
        assert not allowed_ip(ip, config)
    assert allowed_ip('1.1.1.1',config)
    restricted=replace(config, allow_private_targets=True,private_target_cidrs='10.22.0.0/16')
    assert allowed_ip('10.22.1.1',restricted)
    assert not allowed_ip('127.0.0.1',restricted)
    assert not allowed_ip('10.23.0.1',restricted)
    assert not allowed_ip('169.254.169.254',restricted)


def test_repo_escape_denied(tmp_path):
    config=replace(get_settings(), scan_root=tmp_path)
    (tmp_path/'allowed').mkdir()
    assert validate_repo_target('allowed',config)==tmp_path/'allowed'
    with pytest.raises(PolicyDenied): validate_repo_target('../outside',config)
    with pytest.raises(PolicyDenied): validate_repo_target(str(tmp_path),config)
