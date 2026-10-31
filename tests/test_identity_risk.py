from app.api.identity_risk import _signals


def test_privilege_and_failed_login_signals():
    assert _signals('iam.attach_role') == (False, True)
    assert _signals('user.login.failed') == (True, False)
    assert _signals('s3.get_object') == (False, False)
