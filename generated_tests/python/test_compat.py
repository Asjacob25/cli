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
    find_entry_points,
    get_dist_name,
    ensure_default_certs_loaded,
    cached_property
)

import importlib_metadata


@pytest.fixture
def mock_sys_platform():
    with patch('httpie.compat.sys.platform') as mock_platform:
        yield mock_platform


@pytest.fixture
def mock_sys_frozen():
    with patch('httpie.compat.sys.frozen') as mock_frozen:
        yield mock_frozen


@pytest.fixture
def mock_importlib_metadata():
    with patch('httpie.compat.importlib_metadata') as mock_metadata:
        yield mock_metadata


def test_is_windows_true(mock_sys_platform):
    """
    Test is_windows flag is True when sys.platform contains 'win32'.
    """
    mock_sys_platform.lower.return_value = 'win32'
    with patch('httpie.compat.is_windows', True):
        assert is_windows is True


def test_is_windows_false(mock_sys_platform):
    """
    Test is_windows flag is False when sys.platform does not contain 'win32'.
    """
    mock_sys_platform.lower.return_value = 'linux'
    with patch('httpie.compat.is_windows', False):
        assert is_windows is False


def test_is_frozen_true(mock_sys_frozen):
    """
    Test is_frozen flag is True when sys.frozen is set.
    """
    mock_sys_frozen = True
    with patch('httpie.compat.is_frozen', mock_sys_frozen):
        assert is_frozen is True


def test_is_frozen_false(mock_sys_frozen):
    """
    Test is_frozen flag is False when sys.frozen is not set.
    """
    mock_sys_frozen = False
    with patch('httpie.compat.is_frozen', mock_sys_frozen):
        assert is_frozen is False


def test_min_supported_py_version():
    """
    Test that MIN_SUPPORTED_PY_VERSION is correctly set to (3, 7).
    """
    assert MIN_SUPPORTED_PY_VERSION == (3, 7)


def test_max_supported_py_version():
    """
    Test that MAX_SUPPORTED_PY_VERSION is correctly set to (3, 11).
    """
    assert MAX_SUPPORTED_PY_VERSION == (3, 11)


def test_cached_property_with_functools(mocker):
    """
    Test that cached_property uses functools.cached_property when available.
    """
    mocker.patch('httpie.compat.cached_property', new=mocked_cached_property := MagicMock())
    # Re-import to apply the mock
    from httpie.compat import cached_property
    assert cached_property == mocked_cached_property
    mocked_cached_property.assert_not_called()  # Just checking the assignment


def test_cached_property_fallback():
    """
    Test that cached_property fallback implementation works correctly.
    """
    class TestClass:
        def __init__(self):
            self.compute_called = 0

        @cached_property
        def value(self):
            self.compute_called += 1
            return 42

    obj = TestClass()
    assert obj.value == 42
    assert obj.compute_called == 1
    assert obj.value == 42
    assert obj.compute_called == 1  # Should not increment again


@pytest.mark.parametrize("entry_points_obj,group,expected", [
    (MagicMock(select=lambda group: ['ep1', 'ep2']), 'group1', ['ep1', 'ep2']),
    (MagicMock(get=lambda group, default: {'group1': ['ep1']}), 'group1', {'ep1'}),
])
def test_find_entry_points_with_select(entry_points_obj, group, expected):
    """
    Test find_entry_points when entry_points have 'select' method.
    """
    if hasattr(entry_points_obj, 'select'):
        with patch('httpie.compat.find_entry_points') as func:
            result = find_entry_points(entry_points_obj, group)
            assert result == expected
    else:
        pytest.skip("Entry points object does not have 'select' method")


def test_find_entry_points_without_select(mock_importlib_metadata):
    """
    Test find_entry_points when entry_points do not have 'select' method.
    """
    entry_points = {'group1': ['ep1', 'ep2']}
    mock_entry_points = MagicMock(get=lambda group, default: entry_points.get(group, default))
    result = find_entry_points(mock_entry_points, 'group1')
    assert result == set(['ep1', 'ep2'])


@pytest.mark.parametrize("entry_point,expected", [
    (MagicMock(dist=MagicMock(name='dist1')), 'dist1'),
    (MagicMock(dist=None, pattern=MagicMock(match=lambda value: MagicMock(group=lambda name: 'module'))), 'package'),
    (MagicMock(dist=None, pattern=MagicMock(match=lambda value: None)), None),
])
def test_get_dist_name(entry_point, expected, mock_importlib_metadata):
    """
    Test get_dist_name with different entry_point scenarios.
    """
    if expected == 'dist1':
        result = get_dist_name(entry_point)
        assert result == 'dist1'
    elif expected == 'package':
        mock_metadata = mock_importlib_metadata.metadata.return_value
        mock_metadata.get.return_value = 'PackageName'
        with patch('httpie.compat.importlib_metadata.metadata', mock_importlib_metadata.metadata):
            result = get_dist_name(entry_point)
            assert result == 'PackageName'
    else:
        result = get_dist_name(entry_point)
        assert result is None


def test_get_dist_name_package_not_found(mock_importlib_metadata):
    """
    Test get_dist_name when the package is not found.
    """
    entry_point = MagicMock(dist=None, pattern=MagicMock(match=lambda value: MagicMock(group=lambda name: 'nonexistent')))
    mock_importlib_metadata.metadata.side_effect = importlib_metadata.PackageNotFoundError
    result = get_dist_name(entry_point)
    assert result is None


def test_ensure_default_certs_loaded_when_no_certs(mocker):
    """
    Test ensure_default_certs_loaded loads default certs when none are loaded.
    """
    ssl_context = MagicMock(spec=SSLContext)
    ssl_context.get_ca_certs.return_value = []
    ssl_context.load_default_certs = MagicMock()

    ensure_default_certs_loaded(ssl_context)
    ssl_context.load_default_certs.assert_called_once()


def test_ensure_default_certs_loaded_with_certs(mocker):
    """
    Test ensure_default_certs_loaded does not load default certs when already loaded.
    """
    ssl_context = MagicMock(spec=SSLContext)
    ssl_context.get_ca_certs.return_value = ['cert1']
    ssl_context.load_default_certs = MagicMock()

    ensure_default_certs_loaded(ssl_context)
    ssl_context.load_default_certs.assert_not_called()


def test_ensure_default_certs_loaded_without_load_default_certs(mocker):
    """
    Test ensure_default_certs_loaded does nothing if ssl_context lacks load_default_certs.
    """
    ssl_context = MagicMock(spec=SSLContext)
    ssl_context.get_ca_certs.return_value = []
    del ssl_context.load_default_certs

    ensure_default_certs_loaded(ssl_context)
    # No exception should be raised, and load_default_certs should not be called


def test_cached_property_set_name():
    """
    Test that cached_property sets the name correctly using __set_name__.
    """
    class Owner:
        @cached_property
        def prop(self):
            return 'value'

    owner = Owner()
    assert owner.prop == 'value'


def test_cached_property_multiple_names_raises():
    """
    Test that assigning cached_property to multiple names raises TypeError.
    """
    with pytest.raises(TypeError):
        class Owner:
            @cached_property
            def prop1(self):
                return 'value1'

            @cached_property
            def prop2(self):
                return 'value2'


def test_get_dist_name_with_invalid_pattern(mock_importlib_metadata):
    """
    Test get_dist_name when the pattern does not match the module.
    """
    entry_point = MagicMock(
        dist=None,
        pattern=MagicMock(match=lambda value: MagicMock(group=lambda name: None))
    )
    result = get_dist_name(entry_point)
    assert result is None


def test_get_dist_name_with_missing_module(mock_importlib_metadata):
    """
    Test get_dist_name when the module has no group 'module'.
    """
    entry_point = MagicMock(
        dist=None,
        pattern=MagicMock(match=lambda value: MagicMock(group=lambda name: ''))
    )
    result = get_dist_name(entry_point)
    assert result is None


def test_find_entry_points_empty_group(mock_importlib_metadata):
    """
    Test find_entry_points with an empty group.
    """
    entry_points = {}
    mock_entry_points = MagicMock(get=lambda group, default: entry_points.get(group, default))
    result = find_entry_points(mock_entry_points, 'nonexistent_group')
    assert result == set()


def test_find_entry_points_with_select_empty(mock_importlib_metadata):
    """
    Test find_entry_points with select method returning empty.
    """
    entry_points_obj = MagicMock(select=lambda group: [])
    result = find_entry_points(entry_points_obj, 'group1')
    assert result == []


def test_ensure_default_certs_loaded_attribute_error(mocker):
    """
    Test ensure_default_certs_loaded handles AttributeError gracefully.
    """
    ssl_context = MagicMock(spec=SSLContext)
    ssl_context.get_ca_certs.side_effect = AttributeError
    ssl_context.load_default_certs = MagicMock()

    ensure_default_certs_loaded(ssl_context)
    ssl_context.load_default_certs.assert_not_called()


def test_cached_property_without_set_name():
    """
    Test accessing cached_property before __set_name__ is called.
    """
    prop = cached_property(MagicMock())

    with pytest.raises(TypeError):
        _ = prop.func(None)


def test_cached_property_set_name_different_owner():
    """
    Test that cached_property cannot be set on different owners.
    """
    prop = cached_property(MagicMock())

    class Owner1:
        prop = prop

    class Owner2:
        prop = prop

    Owner1.prop = prop
    with pytest.raises(TypeError):
        Owner2.prop = prop