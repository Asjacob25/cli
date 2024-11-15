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
    find_entry_points,
    get_dist_name,
    ensure_default_certs_loaded,
)

# -------------------------------------------------------------------------------------
# Tests for is_windows and is_frozen variables
# -------------------------------------------------------------------------------------

@pytest.mark.parametrize("platform, expected", [
    ("win32", True),
    ("windows", True),
    ("linux", False),
    ("darwin", False),
])
def test_is_windows(platform, expected):
    """
    Test the is_windows variable correctly identifies Windows platforms.
    """
    with mock.patch("sys.platform", platform):
        from httpie.compat import is_windows
        assert is_windows == expected


@pytest.mark.parametrize("frozen, expected", [
    (True, True),
    (False, False),
    (None, False),
])
def test_is_frozen(frozen, expected):
    """
    Test the is_frozen variable correctly identifies frozen applications.
    """
    with mock.patch.dict("sys.__dict__", {"frozen": frozen} if frozen is not None else {}):
        from httpie.compat import is_frozen
        assert is_frozen == expected


# -------------------------------------------------------------------------------------
# Tests for find_entry_points function
# -------------------------------------------------------------------------------------

def test_find_entry_points_with_select():
    """
    Test find_entry_points returns selected entry points when select is available.
    """
    mock_entry_points = MagicMock()
    mock_entry_points.select.return_value = ["ep1", "ep2"]
    group = "test_group"

    result = find_entry_points(mock_entry_points, group)
    mock_entry_points.select.assert_called_once_with(group=group)
    assert result == ["ep1", "ep2"]


def test_find_entry_points_without_select():
    """
    Test find_entry_points returns entry points using get when select is unavailable.
    """
    mock_entry_points = MagicMock()
    del mock_entry_points.select
    mock_entry_points.get.return_value = {"ep1", "ep2"}
    group = "test_group"

    result = find_entry_points(mock_entry_points, group)
    mock_entry_points.get.assert_called_once_with(group, ())
    assert result == {"ep1", "ep2"}


# -------------------------------------------------------------------------------------
# Tests for get_dist_name function
# -------------------------------------------------------------------------------------

@pytest.fixture
def mock_entry_point_with_dist():
    ep = MagicMock()
    ep.dist = MagicMock(name="mock_dist")
    ep.dist.name = "Mock Distribution"
    return ep


@pytest.fixture
def mock_entry_point_without_dist():
    ep = MagicMock()
    del ep.dist
    # Simulate a matching pattern
    mock_match = MagicMock()
    mock_match.group.return_value = "mockmodule.submodule"
    ep.pattern.match.return_value = mock_match
    return ep


def test_get_dist_name_with_dist(mock_entry_point_with_dist):
    """
    Test get_dist_name returns the distribution name when dist attribute is present.
    """
    result = get_dist_name(mock_entry_point_with_dist)
    assert result == "Mock Distribution"


def test_get_dist_name_without_dist_success(mock_entry_point_without_dist):
    """
    Test get_dist_name retrieves the distribution name from metadata when dist is absent.
    """
    with patch("httpie.compat.importlib_metadata.metadata") as mock_metadata:
        mock_metadata.return_value.get.return_value = "Resolved Distribution"
        result = get_dist_name(mock_entry_point_without_dist)
        mock_metadata.assert_called_once_with("mockmodule")
        assert result == "Resolved Distribution"


def test_get_dist_name_without_dist_no_match(mock_entry_point_without_dist):
    """
    Test get_dist_name returns None when the entry point pattern does not match.
    """
    mock_entry_point_without_dist.pattern.match.return_value = None
    result = get_dist_name(mock_entry_point_without_dist)
    assert result is None


def test_get_dist_name_metadata_not_found(mock_entry_point_without_dist):
    """
    Test get_dist_name returns None when the package metadata is not found.
    """
    with patch("httpie.compat.importlib_metadata.metadata", side_effect=importlib_metadata.PackageNotFoundError):
        result = get_dist_name(mock_entry_point_without_dist)
        assert result is None


# -------------------------------------------------------------------------------------
# Tests for ensure_default_certs_loaded function
# -------------------------------------------------------------------------------------

def test_ensure_default_certs_loaded_with_load_default_certs_and_no_ca_certs():
    """
    Test ensure_default_certs_loaded calls load_default_certs when no CA certs are loaded.
    """
    mock_ssl_context = MagicMock(spec=SSLContext)
    mock_ssl_context.get_ca_certs.return_value = []
    mock_ssl_context.load_default_certs = MagicMock()

    ensure_default_certs_loaded(mock_ssl_context)

    mock_ssl_context.get_ca_certs.assert_called_once()
    mock_ssl_context.load_default_certs.assert_called_once()


def test_ensure_default_certs_loaded_with_load_default_certs_and_existing_ca_certs():
    """
    Test ensure_default_certs_loaded does not call load_default_certs when CA certs are already loaded.
    """
    mock_ssl_context = MagicMock(spec=SSLContext)
    mock_ssl_context.get_ca_certs.return_value = ["cert1"]
    mock_ssl_context.load_default_certs = MagicMock()

    ensure_default_certs_loaded(mock_ssl_context)

    mock_ssl_context.get_ca_certs.assert_called_once()
    mock_ssl_context.load_default_certs.assert_not_called()


def test_ensure_default_certs_loaded_without_load_default_certs():
    """
    Test ensure_default_certs_loaded does nothing when ssl_context lacks load_default_certs.
    """
    mock_ssl_context = MagicMock(spec=SSLContext)
    mock_ssl_context.get_ca_certs.return_value = []
    del mock_ssl_context.load_default_certs

    ensure_default_certs_loaded(mock_ssl_context)

    mock_ssl_context.get_ca_certs.assert_called_once()
    # Since load_default_certs does not exist, nothing to assert


# -------------------------------------------------------------------------------------
# Tests for cached_property compatibility class
# -------------------------------------------------------------------------------------

@pytest.mark.skipif(sys.version_info >= (3, 8), reason="cached_property is available in Python 3.8+")
def test_cached_property_behavior():
    """
    Test the custom cached_property behaves correctly in Python versions < 3.8.
    """
    from httpie.compat import cached_property

    class TestClass:
        def __init__(self):
            self.counter = 0

        @cached_property
        def value(self):
            self.counter += 1
            return self.counter

    obj = TestClass()
    assert obj.value == 1
    assert obj.value == 1  # Should not increment again
    assert obj.counter == 1


# -------------------------------------------------------------------------------------
# Additional Tests for Variables and Functions
# -------------------------------------------------------------------------------------

def test_min_supported_py_version():
    """
    Test MIN_SUPPORTED_PY_VERSION is correctly set.
    """
    from httpie.compat import MIN_SUPPORTED_PY_VERSION
    assert MIN_SUPPORTED_PY_VERSION == (3, 7)


def test_max_supported_py_version():
    """
    Test MAX_SUPPORTED_PY_VERSION is correctly set.
    """
    from httpie.compat import MAX_SUPPORTED_PY_VERSION
    assert MAX_SUPPORTED_PY_VERSION == (3, 11)


@pytest.mark.parametrize("py_version, expected_import", [
    ((3, 8), "importlib.metadata"),
    ((3, 7), "importlib_metadata"),
])
def test_importlib_metadata_import(py_version, expected_import):
    """
    Test that importlib_metadata is correctly imported based on Python version.
    """
    with mock.patch("sys.version_info", py_version):
        if py_version >= (3, 8):
            from httpie.compat import importlib_metadata
            assert importlib_metadata.__name__ == "importlib.metadata"
        else:
            from httpie.compat import importlib_metadata
            assert importlib_metadata.__name__ == "importlib_metadata"


# -------------------------------------------------------------------------------------
# Setup and Teardown (if needed)
# -------------------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def setup_teardown():
    """
    Setup actions before each test and teardown actions after each test.
    Currently, no setup or teardown actions are required.
    """
    yield
    # Teardown can be handled here if necessary