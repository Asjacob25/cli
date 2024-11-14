import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

import sys
import pytest
from unittest import mock
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
import importlib_metadata
from httpie.cookies import HTTPieCookiePolicy
from http import cookiejar


@pytest.fixture
def mock_sys_platform():
    with mock.patch('httpie.compat.sys.platform') as mock_platform:
        yield mock_platform


@pytest.fixture
def mock_sys_frozen():
    with mock.patch('httpie.compat.sys.frozen', False):
        yield


@pytest.fixture
def mock_importlib_metadata():
    with mock.patch('httpie.compat.importlib_metadata') as mock_metadata:
        yield mock_metadata


@pytest.fixture
def mock_ssl_context():
    with mock.MagicMock(spec=SSLContext) as ssl_ctx:
        yield ssl_ctx


def test_default_cookie_policy():
    """
    Test that the DefaultCookiePolicy is set to HTTPieCookiePolicy.
    """
    assert cookiejar.DefaultCookiePolicy is HTTPieCookiePolicy


def test_is_windows_true(mock_sys_platform):
    """
    Test is_windows when the platform is Windows.
    """
    mock_sys_platform.lower.return_value = 'win32'
    from httpie.compat import is_windows as iw
    assert iw is True


def test_is_windows_false(mock_sys_platform):
    """
    Test is_windows when the platform is not Windows.
    """
    mock_sys_platform.lower.return_value = 'linux'
    from httpie.compat import is_windows as iw
    assert iw is False


def test_is_frozen_true(mock_sys_frozen):
    """
    Test is_frozen when sys.frozen is True.
    """
    with mock.patch('httpie.compat.getattr', return_value=True):
        from httpie.compat import is_frozen as ifrozen
        assert ifrozen is True


def test_is_frozen_false(mock_sys_frozen):
    """
    Test is_frozen when sys.frozen is False.
    """
    with mock.patch('httpie.compat.getattr', return_value=False):
        from httpie.compat import is_frozen as ifrozen
        assert ifrozen is False


def test_min_supported_py_version():
    """
    Test that MIN_SUPPORTED_PY_VERSION is correctly set.
    """
    from httpie.compat import MIN_SUPPORTED_PY_VERSION as min_py
    assert min_py == (3, 7)


def test_max_supported_py_version():
    """
    Test that MAX_SUPPORTED_PY_VERSION is correctly set.
    """
    from httpie.compat import MAX_SUPPORTED_PY_VERSION as max_py
    assert max_py == (3, 11)


def test_cached_property_import_success():
    """
    Test that cached_property is imported from functools when available.
    """
    with mock.patch.dict('sys.modules', {'functools': mock.MagicMock(cached_property=mock.MagicMock())}):
        from httpie.compat import cached_property as cp
        assert cp is not None


def test_cached_property_fallback():
    """
    Test that cached_property fallback is used when functools.cached_property is not available.
    """
    with mock.patch.dict('sys.modules', {'functools': None}):
        with mock.patch('httpie.compat.cached_property.func', side_effect=TypeError):
            from httpie.compat import cached_property as cp
            assert cp is not None
            with pytest.raises(TypeError):
                cp.func(None)


def test_find_entry_points_select_available(mock_importlib_metadata):
    """
    Test find_entry_points using select method when available.
    """
    mock_eps = mock.MagicMock()
    mock_eps.select.return_value = ['ep1', 'ep2']
    result = find_entry_points(mock_eps, 'group1')
    mock_eps.select.assert_called_once_with(group='group1')
    assert result == ['ep1', 'ep2']


def test_find_entry_points_select_not_available(mock_importlib_metadata):
    """
    Test find_entry_points using get method when select is not available.
    """
    mock_eps = mock.MagicMock()
    del mock_eps.select
    mock_eps.get.return_value = {'group1': ['ep1', 'ep2']}
    result = find_entry_points(mock_eps, 'group1')
    mock_eps.get.assert_called_once_with('group1', ())
    assert result == set(['ep1', 'ep2'])


def test_get_dist_name_with_dist(mock_importlib_metadata):
    """
    Test get_dist_name when entry_point has a dist attribute.
    """
    mock_ep = mock.MagicMock()
    mock_ep.dist.name = 'package_name'
    name = get_dist_name(mock_ep)
    assert name == 'package_name'


def test_get_dist_name_without_dist_with_valid_module(mock_importlib_metadata):
    """
    Test get_dist_name when entry_point has no dist but has a valid module.
    """
    mock_ep = mock.MagicMock()
    mock_ep.dist = None
    mock_ep.pattern.match.return_value.group.return_value = 'module.submodule'
    mock_importlib_metadata.metadata.return_value.get.return_value = 'PackageName'
    name = get_dist_name(mock_ep)
    mock_importlib_metadata.metadata.assert_called_once_with('module')
    assert name == 'PackageName'


def test_get_dist_name_without_dist_with_invalid_module(mock_importlib_metadata):
    """
    Test get_dist_name when entry_point has no dist and module pattern does not match.
    """
    mock_ep = mock.MagicMock()
    mock_ep.dist = None
    mock_ep.pattern.match.return_value = None
    name = get_dist_name(mock_ep)
    assert name is None


def test_get_dist_name_package_not_found(mock_importlib_metadata):
    """
    Test get_dist_name when the package is not found.
    """
    mock_ep = mock.MagicMock()
    mock_ep.dist = None
    mock_ep.pattern.match.return_value.group.return_value = 'unknown.module'
    mock_importlib_metadata.metadata.side_effect = importlib_metadata.PackageNotFoundError
    name = get_dist_name(mock_ep)
    assert name is None


def test_ensure_default_certs_loaded_when_load_available_and_no_certs(mock_ssl_context):
    """
    Test ensure_default_certs_loaded when load_default_certs is available and no certs are loaded.
    """
    mock_ssl_context.get_ca_certs.return_value = []
    ensure_default_certs_loaded(mock_ssl_context)
    mock_ssl_context.load_default_certs.assert_called_once()


def test_ensure_default_certs_loaded_when_load_available_and_certs_present(mock_ssl_context):
    """
    Test ensure_default_certs_loaded when load_default_certs is available and certs are already loaded.
    """
    mock_ssl_context.get_ca_certs.return_value = ['cert1']
    ensure_default_certs_loaded(mock_ssl_context)
    mock_ssl_context.load_default_certs.assert_not_called()


def test_ensure_default_certs_loaded_without_load(mock_ssl_context):
    """
    Test ensure_default_certs_loaded when load_default_certs is not available.
    """
    del mock_ssl_context.load_default_certs
    ensure_default_certs_loaded(mock_ssl_context)
    mock_ssl_context.get_ca_certs.assert_called_once()


@pytest.mark.parametrize("py_version, expected", [
    ((3, 7), True),
    ((3, 6), False),
    ((3, 8), True),
])
def test_python_version_support(py_version, expected):
    """
    Test that the Python version is within the supported range.
    """
    with mock.patch('httpie.compat.sys.version_info', py_version):
        from httpie.compat import MIN_SUPPORTED_PY_VERSION, MAX_SUPPORTED_PY_VERSION
        is_supported = MIN_SUPPORTED_PY_VERSION <= py_version <= MAX_SUPPORTED_PY_VERSION
        assert is_supported is expected