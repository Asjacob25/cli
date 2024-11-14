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
    find_entry_points,
    get_dist_name,
    ensure_default_certs_loaded,
    cached_property,
    MIN_SUPPORTED_PY_VERSION,
    MAX_SUPPORTED_PY_VERSION,
)
import importlib_metadata


@pytest.fixture
def mock_sys_platform():
    with mock.patch('httpie.compat.sys.platform') as mock_platform:
        yield mock_platform


@pytest.fixture
def mock_sys_frozen():
    with mock.patch('httpie.compat.sys.frozen', False) as mock_frozen:
        yield mock_frozen


def test_is_windows_true(mock_sys_platform):
    """Test is_windows is True when sys.platform contains 'win32'."""
    mock_sys_platform.return_value = 'win32'
    assert is_windows is True


def test_is_windows_false(mock_sys_platform):
    """Test is_windows is False when sys.platform does not contain 'win32'."""
    mock_sys_platform.return_value = 'linux'
    assert is_windows is False


def test_is_frozen_true(mock_sys_frozen):
    """Test is_frozen is True when sys.frozen is True."""
    mock_sys_frozen.return_value = True
    assert is_frozen is True


def test_is_frozen_false(mock_sys_frozen):
    """Test is_frozen is False when sys.frozen is False."""
    mock_sys_frozen.return_value = False
    assert is_frozen is False


def test_min_supported_py_version():
    """Test MIN_SUPPORTED_PY_VERSION is correctly set."""
    assert MIN_SUPPORTED_PY_VERSION == (3, 7)


def test_max_supported_py_version():
    """Test MAX_SUPPORTED_PY_VERSION is correctly set."""
    assert MAX_SUPPORTED_PY_VERSION == (3, 11)


@pytest.mark.parametrize("python_version,expected", [
    ((3, 8), True),
    ((3, 7), False),
])
def test_cached_property_existing(python_version, expected):
    """
    Test that cached_property is imported when available.

    Args:
        python_version (tuple): Python version to simulate.
        expected (bool): Whether cached_property should be the one from functools.
    """
    with mock.patch('httpie.compat.sys.version_info', mock.Mock(
        __ge__=lambda other: python_version >= other
    )):
        with mock.patch.dict('sys.modules', {'functools': mock.Mock(cached_property=mock.Mock())}):
            if python_version >= (3, 8):
                from httpie.compat import cached_property
                assert cached_property == mock.Mock()
            else:
                from httpie.compat import cached_property
                assert cached_property.__doc__ is not None


def test_find_entry_points_with_select():
    """Test find_entry_points using the select method (Python 3.10+)."""
    mock_entry_points = mock.Mock()
    mock_entry_points.select.return_value = ['entry1', 'entry2']
    group = 'test_group'
    result = find_entry_points(mock_entry_points, group)
    mock_entry_points.select.assert_called_once_with(group=group)
    assert result == ['entry1', 'entry2']


def test_find_entry_points_without_select():
    """Test find_entry_points without the select method (pre-Python 3.10)."""
    mock_entry_points = {
        'test_group': ['entry1', 'entry2']
    }
    group = 'test_group'
    result = find_entry_points(mock_entry_points, group)
    assert result == set(['entry1', 'entry2'])


def test_get_dist_name_with_dist():
    """Test get_dist_name when entry_point has a dist attribute."""
    mock_entry_point = mock.Mock()
    mock_entry_point.dist.name = 'mock_dist'
    result = get_dist_name(mock_entry_point)
    assert result == 'mock_dist'


def test_get_dist_name_without_dist_valid_module():
    """Test get_dist_name when entry_point does not have a dist and pattern matches a valid module."""
    mock_entry_point = mock.Mock()
    mock_entry_point.dist = None
    mock_entry_point.value = 'mock_module.submodule'
    pattern_mock = mock.Mock()
    pattern_mock.match.return_value = mock.Mock(group=lambda x: 'mock_module')
    mock_entry_point.pattern = pattern_mock

    with mock.patch('httpie.compat.importlib_metadata.metadata') as mock_metadata:
        mock_metadata.return_value.get.return_value = 'Mock Package'
        result = get_dist_name(mock_entry_point)
        mock_metadata.assert_called_once_with('mock_module')
        assert result == 'Mock Package'


def test_get_dist_name_without_dist_invalid_module():
    """Test get_dist_name when entry_point does not have a dist and pattern does not match."""
    mock_entry_point = mock.Mock()
    mock_entry_point.dist = None
    mock_entry_point.value = 'invalid_module.submodule'
    pattern_mock = mock.Mock()
    pattern_mock.match.return_value = None
    mock_entry_point.pattern = pattern_mock

    result = get_dist_name(mock_entry_point)
    assert result is None


def test_get_dist_name_metadata_not_found():
    """Test get_dist_name when metadata retrieval raises PackageNotFoundError."""
    mock_entry_point = mock.Mock()
    mock_entry_point.dist = None
    mock_entry_point.value = 'nonexistent_module.submodule'
    pattern_mock = mock.Mock()
    pattern_mock.match.return_value = mock.Mock(group=lambda x: 'nonexistent_module')
    mock_entry_point.pattern = pattern_mock

    with mock.patch('httpie.compat.importlib_metadata.metadata') as mock_metadata:
        mock_metadata.side_effect = importlib_metadata.PackageNotFoundError
        result = get_dist_name(mock_entry_point)
        mock_metadata.assert_called_once_with('nonexistent_module')
        assert result is None


def test_ensure_default_certs_loaded_with_load_default_certs():
    """Test ensure_default_certs_loaded when ssl_context has load_default_certs and no CA certs."""
    mock_ssl_context = mock.Mock(spec=SSLContext)
    mock_ssl_context.get_ca_certs.return_value = []
    ensure_default_certs_loaded(mock_ssl_context)
    mock_ssl_context.load_default_certs.assert_called_once()


def test_ensure_default_certs_loaded_with_load_default_certs_already_loaded():
    """Test ensure_default_certs_loaded when ssl_context already has CA certs."""
    mock_ssl_context = mock.Mock(spec=SSLContext)
    mock_ssl_context.get_ca_certs.return_value = ['cert']
    ensure_default_certs_loaded(mock_ssl_context)
    mock_ssl_context.load_default_certs.assert_not_called()


def test_ensure_default_certs_loaded_without_load_default_certs():
    """Test ensure_default_certs_loaded when ssl_context does not have load_default_certs."""
    mock_ssl_context = mock.Mock(spec=SSLContext)
    del mock_ssl_context.load_default_certs
    ensure_default_certs_loaded(mock_ssl_context)
    # Should not raise an AttributeError


class TestCachedPropertyFallback:
    """Tests for the fallback cached_property implementation."""

    def test_cached_property_initialization(self):
        """Test initializing the cached_property."""
        def func(instance):
            return 'value'

        prop = cached_property(func)
        assert prop.real_func == func
        assert prop.__doc__ == func.__doc__

    def test_set_name_success(self):
        """Test setting the name of a cached_property."""
        def func(instance):
            return 'value'

        prop = cached_property(func)
        owner = mock.Mock()
        prop.__set_name__(owner, 'test_prop')
        assert prop.name == 'test_prop'
        assert prop.func == func

    def test_set_name_conflict(self):
        """Test setting the name of a cached_property to a different name raises TypeError."""
        def func(instance):
            return 'value'

        prop = cached_property(func)
        owner = mock.Mock()
        prop.__set_name__(owner, 'prop_one')
        with pytest.raises(TypeError, match="Cannot assign the same cached_property to two different names"):
            prop.__set_name__(owner, 'prop_two')

    def test_get_cached_property(self):
        """Test retrieving the cached_property value."""
        def func(instance):
            return 'cached_value'

        prop = cached_property(func)
        owner = mock.Mock()
        instance = mock.Mock(__dict__={})
        prop.__set_name__(owner, 'test_prop')
        result = prop.__get__(instance, owner)
        instance.__dict__.__setitem__.assert_called_once_with('test_prop', 'cached_value')
        assert result == 'cached_value'

    def test_get_cached_property_instance_none(self):
        """Test retrieving the cached_property when instance is None."""
        def func(instance):
            return 'cached_value'

        prop = cached_property(func)
        owner = mock.Mock()
        result = prop.__get__(None, owner)
        assert result == prop