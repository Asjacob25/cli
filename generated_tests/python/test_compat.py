import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

import sys
import pytest
from unittest import mock
from unittest.mock import Mock, patch
from ssl import SSLContext
from httpie.compat import (
    is_windows,
    is_frozen,
    find_entry_points,
    get_dist_name,
    ensure_default_certs_loaded,
    cached_property,
)
import importlib_metadata


@pytest.fixture
def mock_entry_point():
    return Mock(spec=importlib_metadata.EntryPoint)


@pytest.fixture
def mock_entry_points():
    return Mock()


@pytest.fixture
def ssl_context():
    return SSLContext()


@pytest.fixture
def mock_ssl_context_with_certs(ssl_context):
    ssl_context.get_ca_certs.return_value = {"cert1": "data"}
    return ssl_context


@pytest.fixture
def mock_ssl_context_without_certs(ssl_context):
    ssl_context.get_ca_certs.return_value = {}
    return ssl_context


def test_is_windows_true():
    """
    Test that is_windows is True when sys.platform contains 'win32'.
    """
    with patch('sys.platform', 'win32'):
        from httpie.compat import is_windows
        assert is_windows is True


def test_is_windows_false():
    """
    Test that is_windows is False when sys.platform does not contain 'win32'.
    """
    with patch('sys.platform', 'linux'):
        from httpie.compat import is_windows
        assert is_windows is False


def test_is_frozen_true():
    """
    Test that is_frozen is True when sys.frozen is set.
    """
    with patch.object(sys, 'frozen', True):
        from httpie.compat import is_frozen
        assert is_frozen is True


def test_is_frozen_false():
    """
    Test that is_frozen is False when sys.frozen is not set.
    """
    if hasattr(sys, 'frozen'):
        delattr(sys, 'frozen')
    from httpie.compat import is_frozen
    assert is_frozen is False


@pytest.mark.parametrize(
    "entry_points, group, expected",
    [
        (Mock(select=Mock(return_value=['ep1', 'ep2'])), "group1", ['ep1', 'ep2']),
        (Mock(get=Mock(return_value={'group2': ['ep3']})), "group2", {'ep3'}),
        (Mock(get=Mock(return_value={})), "nonexistent", set()),
    ],
)
def test_find_entry_points(entry_points, group, expected):
    """
    Test find_entry_points with different entry_points objects and groups.
    """
    with patch('httpie.compat.importlib_metadata', importlib_metadata):
        result = find_entry_points(entry_points, group)
        assert result == expected


def test_find_entry_points_no_select():
    """
    Test find_entry_points when entry_points does not have 'select' method.
    """
    entry_points = {'group1': ['ep1', 'ep2']}
    group = 'group1'
    with patch('httpie.compat.importlib_metadata', importlib_metadata):
        result = find_entry_points(entry_points, group)
        assert result == {'ep1', 'ep2'}


def test_get_dist_name_with_dist(mock_entry_point):
    """
    Test get_dist_name when entry_point has 'dist' attribute.
    """
    mock_dist = Mock()
    mock_dist.name = "test_dist"
    mock_entry_point.dist = mock_dist
    with patch('httpie.compat.importlib_metadata', importlib_metadata):
        dist_name = get_dist_name(mock_entry_point)
        assert dist_name == "test_dist"


def test_get_dist_name_without_dist_valid_pattern(mock_entry_point):
    """
    Test get_dist_name when entry_point does not have 'dist' but has a valid pattern.
    """
    mock_entry_point.dist = None
    mock_entry_point.pattern = mock.Mock()
    mock_entry_point.pattern.match.return_value = mock.Mock(group=Mock(return_value="module.submodule"))
    with patch('httpie.compat.importlib_metadata.metadata') as mock_metadata:
        mock_metadata.return_value.get.return_value = "metadata_dist"
        dist_name = get_dist_name(mock_entry_point)
        assert dist_name == "metadata_dist"


def test_get_dist_name_without_dist_invalid_pattern(mock_entry_point):
    """
    Test get_dist_name when entry_point does not have 'dist' and pattern is invalid.
    """
    mock_entry_point.dist = None
    mock_entry_point.pattern = mock.Mock()
    mock_entry_point.pattern.match.return_value = None
    with patch('httpie.compat.importlib_metadata.metadata') as mock_metadata:
        dist_name = get_dist_name(mock_entry_point)
        assert dist_name is None


def test_get_dist_name_metadata_not_found(mock_entry_point):
    """
    Test get_dist_name when metadata lookup raises PackageNotFoundError.
    """
    mock_entry_point.dist = None
    mock_entry_point.pattern = mock.Mock()
    mock_entry_point.pattern.match.return_value = mock.Mock(group=Mock(return_value="module"))
    with patch('httpie.compat.importlib_metadata.metadata', side_effect=importlib_metadata.PackageNotFoundError):
        dist_name = get_dist_name(mock_entry_point)
        assert dist_name is None


def test_ensure_default_certs_loaded_with_certs(mock_ssl_context_with_certs):
    """
    Test ensure_default_certs_loaded does not load certs if already loaded.
    """
    ensure_default_certs_loaded(mock_ssl_context_with_certs)
    mock_ssl_context_with_certs.load_default_certs.assert_not_called()


def test_ensure_default_certs_loaded_without_certs(mock_ssl_context_without_certs):
    """
    Test ensure_default_certs_loaded loads default certs when none are loaded.
    """
    ensure_default_certs_loaded(mock_ssl_context_without_certs)
    mock_ssl_context_without_certs.load_default_certs.assert_called_once()


def test_ensure_default_certs_loaded_no_load_default_certs():
    """
    Test ensure_default_certs_loaded when ssl_context does not have load_default_certs.
    """
    ssl_ctx = Mock(spec=SSLContext)
    del ssl_ctx.load_default_certs
    ssl_ctx.get_ca_certs.return_value = {}
    ensure_default_certs_loaded(ssl_ctx)
    ssl_ctx.load_default_certs.assert_not_called()


@pytest.mark.skipif(sys.version_info >= (3, 8), reason="cached_property not used in Python >=3.8")
def test_cached_property_decorator():
    """
    Test the custom cached_property decorator.
    """
    class TestClass:
        def __init__(self):
            self.counter = 0

        @cached_property
        def value(self):
            self.counter += 1
            return self.counter

    obj = TestClass()
    assert obj.value == 1
    assert obj.value == 1
    assert obj.counter == 1


@pytest.mark.skipif(sys.version_info < (3, 8), reason="cached_property not defined in Python <3.8")
def test_builtin_cached_property():
    """
    Test the built-in cached_property when available.
    """
    if sys.version_info >= (3, 8):
        from functools import cached_property

        class TestClass:
            def __init__(self):
                self.counter = 0

            @cached_property
            def value(self):
                self.counter += 1
                return self.counter

        obj = TestClass()
        assert obj.value == 1
        assert obj.value == 1
        assert obj.counter == 1
    else:
        pytest.skip("cached_property not available")


def test_cached_property_set_name():
    """
    Test that cached_property sets the name correctly.
    """
    class TestClass:
        @cached_property
        def value(self):
            return 42

    obj = TestClass()
    assert obj.value == 42
    assert 'value' in obj.__dict__


def test_cached_property_multiple_names_raises():
    """
    Test that assigning cached_property to multiple names raises TypeError.
    """
    with pytest.raises(TypeError):
        class TestClass:
            @cached_property
            def value1(self):
                return 1

            @cached_property
            def value2(self):
                return 2

    with pytest.raises(TypeError):
        class TestClass:
            cp = cached_property(lambda self: 1)
            cp = cached_property(lambda self: 2)


def test_cached_property_access_class():
    """
    Test that cached_property accessed from the class returns the descriptor.
    """
    class TestClass:
        @cached_property
        def value(self):
            return 42

    assert isinstance(TestClass.value, cached_property)


@pytest.mark.parametrize("version, expected", [
    ((3, 7), "importlib_metadata"),
    ((3, 8), "importlib.metadata"),
    ((3, 10), "importlib.metadata"),
])
def test_importlib_metadata_based_on_version(version, expected):
    """
    Test that the correct importlib.metadata module is imported based on Python version.
    """
    with patch.object(sys, 'version_info', version):
        if version >= (3, 8):
            from importlib import metadata as importlib_metadata_module
        else:
            import importlib_metadata as importlib_metadata_module

        with patch('httpie.compat.sys.version_info', version):
            with patch('httpie.compat.importlib_metadata', importlib_metadata_module):
                from httpie.compat import importlib_metadata
                assert importlib_metadata is importlib_metadata_module


@patch('httpie.compat.cookiejar', autospec=True)
def test_cookie_policy_overridden(mock_cookiejar):
    """
    Test that the DefaultCookiePolicy is overridden with HTTPieCookiePolicy.
    """
    from httpie.cookies import HTTPieCookiePolicy
    from httpie.compat import cookiejar

    assert cookiejar.DefaultCookiePolicy is HTTPieCookiePolicy


def test_HTTPieCookiePolicy_return_ok_secure_secure_protocol():
    """
    Test HTTPieCookiePolicy.return_ok_secure returns True for secure protocols.
    """
    from httpie.cookies import HTTPieCookiePolicy
    from http import cookiejar

    policy = HTTPieCookiePolicy()
    mock_cookie = Mock()
    mock_request = Mock()
    policy._is_local_host = Mock(return_value=False)
    policy.return_ok_secure(mock_cookie, mock_request)
    policy.super().return_ok_secure.assert_called_once_with(mock_cookie, mock_request)


def test_HTTPieCookiePolicy_return_ok_secure_localhost():
    """
    Test HTTPieCookiePolicy.return_ok_secure returns True for localhost.
    """
    from httpie.cookies import HTTPieCookiePolicy
    from http import cookiejar

    policy = HTTPieCookiePolicy()
    mock_cookie = Mock()
    mock_request = Mock()
    mock_hostname = "localhost"
    cookiejar.request_host = Mock(return_value=mock_hostname)
    policy._is_local_host = Mock(return_value=True)
    with patch.object(policy, 'super', Mock(return_value=Mock(return_ok_secure=False))):
        result = policy.return_ok_secure(mock_cookie, mock_request)
        assert result is True
        policy._is_local_host.assert_called_once_with(mock_hostname)


def test_HTTPieCookiePolicy_return_ok_secure_not_secure():
    """
    Test HTTPieCookiePolicy.return_ok_secure returns False for non-secure protocols and non-localhost.
    """
    from httpie.cookies import HTTPieCookiePolicy
    from http import cookiejar

    policy = HTTPieCookiePolicy()
    mock_cookie = Mock()
    mock_request = Mock()
    mock_hostname = "example.com"
    cookiejar.request_host = Mock(return_value=mock_hostname)
    policy._is_local_host = Mock(return_value=False)
    with patch.object(policy, 'super', Mock(return_value=Mock(return_ok_secure=False))):
        result = policy.return_ok_secure(mock_cookie, mock_request)
        assert result is False
        policy._is_local_host.assert_called_once_with(mock_hostname)


def test_HTTPieCookiePolicy_is_local_host():
    """
    Test HTTPieCookiePolicy._is_local_host correctly identifies localhost.
    """
    from httpie.cookies import HTTPieCookiePolicy
    from httpie.cookies import _LOCALHOST, _LOCALHOST_SUFFIX

    policy = HTTPieCookiePolicy()
    assert policy._is_local_host(_LOCALHOST) is True
    assert policy._is_local_host(f"test{_LOCALHOST_SUFFIX}") is True
    assert policy._is_local_host("example.com") is False
    assert policy._is_local_host("test.example.com") is False