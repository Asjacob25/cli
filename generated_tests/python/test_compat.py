import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

import pytest
from unittest.mock import patch, MagicMock
from ssl import SSLContext
import sys
from httpie.compat import (
    is_windows,
    is_frozen,
    MIN_SUPPORTED_PY_VERSION,
    MAX_SUPPORTED_PY_VERSION,
    cached_property,
    find_entry_points,
    get_dist_name,
    ensure_default_certs_loaded,
    importlib_metadata
)

# Setup and teardown functions if needed


@pytest.fixture(scope="function")
def setup_ssl_context():
    context = SSLContext()
    yield context
    # No specific teardown needed, but could be used to reset changes to context


# Test cases

def test_is_windows():
    """Test if is_windows reflects the current OS correctly."""
    assert is_windows == ('win32' in sys.platform.lower())


def test_is_frozen():
    """Test if is_frozen reflects the sys.frozen flag correctly."""
    assert is_frozen == hasattr(sys, 'frozen')


@pytest.mark.parametrize("py_version, expected", [
    ((3, 6), False),
    ((3, 7), True),
    ((3, 9), True),
    ((3, 12), False),
])
def test_py_version_support(py_version, expected):
    """Test if the Python version is correctly identified as supported or not."""
    result = MIN_SUPPORTED_PY_VERSION <= py_version <= MAX_SUPPORTED_PY_VERSION
    assert result is expected


def test_cached_property():
    """Test the cached_property decorator for expected behavior."""
    class TestClass:
        def __init__(self, value):
            self._value = value

        @cached_property
        def value(self):
            return self._value

    instance = TestClass(10)
    assert instance.value == 10


def test_cached_property_error_without_set_name():
    """Test that accessing cached property without __set_name__ being called raises error."""
    with pytest.raises(TypeError):
        class TestClass:
            @cached_property
            def broken_property(self):
                return "This should not work"

            broken_property.__get__(None)


@patch("httpie.compat.importlib_metadata")
def test_find_entry_points(mock_metadata):
    """Test if find_entry_points selects the correct entry points."""
    mock_metadata.EntryPoint = MagicMock()
    mock_entry_points = MagicMock()
    mock_entry_points.select.return_value = {"test": "entry_point"}
    result = find_entry_points(mock_entry_points, "test")
    assert "test" in result


@patch("httpie.compat.importlib_metadata")
def test_get_dist_name_found(mock_metadata):
    """Test if get_dist_name correctly finds the distribution name."""
    entry_point = MagicMock()
    entry_point.dist = MagicMock(name="test_dist")
    result = get_dist_name(entry_point)
    assert result == "test_dist"


@patch("httpie.compat.importlib_metadata")
def test_get_dist_name_not_found(mock_metadata):
    """Test if get_dist_name returns None when distribution is not found."""
    entry_point = MagicMock()
    entry_point.dist = None
    result = get_dist_name(entry_point)
    assert result is None


@pytest.mark.parametrize("has_load_default_certs, ca_certs", [
    (True, []),
    (True, ['cert']),
    (False, []),
])
def test_ensure_default_certs_loaded(setup_ssl_context, has_load_default_certs, ca_certs):
    """Test ensure_default_certs_loaded under different conditions."""
    ssl_context = setup_ssl_context
    ssl_context.load_default_certs = MagicMock() if has_load_default_certs else None
    ssl_context.get_ca_certs = MagicMock(return_value=ca_certs)
    ensure_default_certs_loaded(ssl_context)
    if has_load_default_certs and not ca_certs:
        ssl_context.load_default_certs.assert_called_once()
    else:
        assert not hasattr(ssl_context, "load_default_certs") or ssl_context.load_default_certs.call_count == 0