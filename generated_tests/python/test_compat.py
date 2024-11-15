import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

import sys
import pytest
from unittest import mock
from unittest.mock import MagicMock, patch
from ssl import SSLContext
from httpie.compat import (
    is_windows,
    is_frozen,
    MIN_SUPPORTED_PY_VERSION,
    MAX_SUPPORTED_PY_VERSION,
    cached_property,
    find_entry_points,
    get_dist_name,
    ensure_default_certs_loaded,
)
from httpie.cookies import HTTPieCookiePolicy
from importlib_metadata import EntryPoint, PackageNotFoundError


@pytest.fixture
def mock_entry_points():
    with patch('httpie.compat.importlib_metadata.entry_points') as mock_ep:
        yield mock_ep


@pytest.fixture
def mock_metadata():
    with patch('httpie.compat.importlib_metadata.metadata') as mock_meta:
        yield mock_meta


@pytest.fixture
def ssl_context():
    return SSLContext()


def test_is_windows():
    """
    Test the is_windows flag based on different sys.platform values.
    """
    with patch('sys.platform', 'win32'):
        from httpie.compat import is_windows
        assert is_windows is True

    with patch('sys.platform', 'linux'):
        from httpie.compat import is_windows
        assert is_windows is False


def test_is_frozen():
    """
    Test the is_frozen flag based on the presence of sys.frozen.
    """
    with patch.object(sys, 'frozen', True):
        from httpie.compat import is_frozen
        assert is_frozen is True

    with patch.object(sys, 'frozen', False):
        from httpie.compat import is_frozen
        assert is_frozen is False


def test_min_supported_py_version():
    """
    Test the minimum supported Python version.
    """
    from httpie.compat import MIN_SUPPORTED_PY_VERSION
    assert MIN_SUPPORTED_PY_VERSION == (3, 7)


def test_max_supported_py_version():
    """
    Test the maximum supported Python version.
    """
    from httpie.compat import MAX_SUPPORTED_PY_VERSION
    assert MAX_SUPPORTED_PY_VERSION == (3, 11)


def test_cached_property_available(monkeypatch):
    """
    Test that cached_property is imported from functools when available.
    """
    monkeypatch.setattr('httpie.compat.cached_property', cached_property)
    from functools import cached_property as expected
    from httpie.compat import cached_property as actual
    assert actual is expected


def test_cached_property_fallback():
    """
    Test that cached_property fallback is used when functools.cached_property is unavailable.
    """
    with patch.dict('sys.modules', {'functools': MagicMock(cached_property=AttributeError)}):
        from httpie.compat import cached_property
        assert hasattr(cached_property, 'func')
        assert callable(cached_property.func)

    with patch('httpie.compat.cached_property', create=True):
        from httpie.compat import cached_property
        assert hasattr(cached_property, '__get__')
        assert hasattr(cached_property, '__set_name__')


def test_find_entry_points_select_method_available(mock_entry_points):
    """
    Test find_entry_points when entry_points has a select method (Python 3.10+).
    """
    group = 'console_scripts'
    mock_ep.select.return_value = ['ep1', 'ep2']
    result = find_entry_points(mock_ep, group)
    mock_ep.select.assert_called_with(group=group)
    assert result == ['ep1', 'ep2']


def test_find_entry_points_select_method_unavailable(mock_entry_points):
    """
    Test find_entry_points when entry_points does not have a select method.
    """
    group = 'console_scripts'
    mock_ep.select.side_effect = AttributeError
    mock_ep.get.return_value = {'console_scripts': ['ep1', 'ep2']}
    result = find_entry_points(mock_ep, group)
    mock_ep.get.assert_called_with(group, ())
    assert result == set(['ep1', 'ep2'])


def test_get_dist_name_with_dist(mock_metadata):
    """
    Test get_dist_name when entry_point has a dist attribute (Python 3.10+).
    """
    entry_point = MagicMock(spec=EntryPoint)
    entry_point.dist = MagicMock(name='test_dist')
    name = get_dist_name(entry_point)
    assert name == 'test_dist'


def test_get_dist_name_without_dist_with_valid_module(mock_metadata):
    """
    Test get_dist_name when entry_point does not have a dist but has a valid module.
    """
    entry_point = MagicMock(spec=EntryPoint)
    entry_point.value = 'testmodule.submodule'
    pattern_mock = MagicMock()
    pattern_mock.match.return_value.group.side_effect = lambda x: 'testmodule' if x == 'module' else None
    entry_point.pattern = pattern_mock

    mock_metadata.return_value = {'Name': 'Test Package'}
    name = get_dist_name(entry_point)
    assert name == 'Test Package'


def test_get_dist_name_without_dist_with_invalid_module(mock_metadata):
    """
    Test get_dist_name when entry_point does not have a dist and module pattern does not match.
    """
    entry_point = MagicMock(spec=EntryPoint)
    entry_point.value = 'invalidmodule.submodule'
    pattern_mock = MagicMock()
    pattern_mock.match.return_value = None
    entry_point.pattern = pattern_mock

    name = get_dist_name(entry_point)
    assert name is None


def test_get_dist_name_package_not_found(mock_metadata):
    """
    Test get_dist_name when the package is not found.
    """
    entry_point = MagicMock(spec=EntryPoint)
    entry_point.value = 'testmodule.submodule'
    pattern_mock = MagicMock()
    pattern_mock.match.return_value.group.side_effect = lambda x: 'testmodule' if x == 'module' else None
    entry_point.pattern = pattern_mock

    mock_metadata.side_effect = PackageNotFoundError

    name = get_dist_name(entry_point)
    assert name is None


def test_ensure_default_certs_loaded_with_ca_certs(ssl_context):
    """
    Test ensure_default_certs_loaded when CA certificates are already loaded.
    """
    ssl_context.get_ca_certs.return_value = [{'issuer': 'Test CA'}]
    ensure_default_certs_loaded(ssl_context)
    ssl_context.load_default_certs.assert_not_called()


def test_ensure_default_certs_loaded_without_ca_certs(ssl_context):
    """
    Test ensure_default_certs_loaded when CA certificates are not loaded.
    """
    ssl_context.get_ca_certs.return_value = []
    ensure_default_certs_loaded(ssl_context)
    ssl_context.load_default_certs.assert_called_once()


def test_httpie_cookie_policy_return_ok_secure_secure_request():
    """
    Test HTTPieCookiePolicy.return_ok_secure for secure protocols.
    """
    policy = HTTPieCookiePolicy()
    cookie = MagicMock()
    request = MagicMock()
    request_scheme = 'https'
    with patch('httpie.compat.cookiejar.request_host', return_value='example.com'):
        with patch.object(cookie, 'secure', True):
            with patch.object(cookie, 'domain', 'example.com'):
                result = policy.return_ok_secure(cookie, request)
                assert result is True


def test_httpie_cookie_policy_return_ok_secure_localhost():
    """
    Test HTTPieCookiePolicy.return_ok_secure for localhost.
    """
    policy = HTTPieCookiePolicy()
    cookie = MagicMock()
    request = MagicMock()
    with patch('httpie.compat.cookiejar.request_host', return_value='localhost'):
        with patch.object(cookie, 'secure', False):
            result = policy.return_ok_secure(cookie, request)
            assert result is True


def test_httpie_cookie_policy_return_ok_secure_insecure_non_localhost():
    """
    Test HTTPieCookiePolicy.return_ok_secure for insecure protocols and non-localhost.
    """
    policy = HTTPieCookiePolicy()
    cookie = MagicMock()
    request = MagicMock()
    with patch('httpie.compat.cookiejar.request_host', return_value='example.com'):
        with patch.object(cookie, 'secure', False):
            result = policy.return_ok_secure(cookie, request)
            assert result is False


def test_httpie_cookie_policy_is_local_host_exact():
    """
    Test HTTPieCookiePolicy._is_local_host with exact 'localhost'.
    """
    policy = HTTPieCookiePolicy()
    assert policy._is_local_host('localhost') is True


def test_httpie_cookie_policy_is_local_host_suffix():
    """
    Test HTTPieCookiePolicy._is_local_host with hostname ending with '.localhost'.
    """
    policy = HTTPieCookiePolicy()
    assert policy._is_local_host('sub.localhost') is True


def test_httpie_cookie_policy_is_local_host_false():
    """
    Test HTTPieCookiePolicy._is_local_host with hostname not related to localhost.
    """
    policy = HTTPieCookiePolicy()
    assert policy._is_local_host('example.com') is False


def test_httpie_cookie_policy_set_name_on_set_name():
    """
    Test HTTPieCookiePolicy.__set_name__ correctly sets the name.
    """
    policy = HTTPieCookiePolicy()
    owner = MagicMock()
    policy.__set_name__(owner, 'test_name')
    assert policy.name == 'test_name'
    assert policy.func is policy.real_func


def test_httpie_cookie_policy_set_name_conflict():
    """
    Test HTTPieCookiePolicy.__set_name__ raises TypeError on name conflict.
    """
    policy = HTTPieCookiePolicy()
    owner = MagicMock()
    policy.__set_name__(owner, 'test_name')

    with pytest.raises(TypeError):
        policy.__set_name__(owner, 'other_name')


def test_httpie_cookie_policy_get_cached(instance_with_name):
    """
    Test HTTPieCookiePolicy.__get__ caches the value on the instance.
    """
    policy = HTTPieCookiePolicy()
    owner = MagicMock()
    instance = MagicMock()
    instance.__dict__ = {}
    policy.__set_name__(owner, 'cached_attr')

    def fake_func(inst):
        return 'cached_value'

    policy.func = fake_func
    result = policy.__get__(instance, owner)
    assert result == 'cached_value'
    assert instance.__dict__['cached_attr'] == 'cached_value'


def test_httpie_cookie_policy_get_without_instance():
    """
    Test HTTPieCookiePolicy.__get__ returns self when instance is None.
    """
    policy = HTTPieCookiePolicy()
    owner = MagicMock()
    assert policy.__get__(None, owner) is policy


def test_httpie_cookie_policy_func_not_set():
    """
    Test HTTPieCookiePolicy.func raises TypeError if not set properly.
    """
    policy = HTTPieCookiePolicy()
    owner = MagicMock()
    with pytest.raises(TypeError):
        policy.__get__(MagicMock(), owner)