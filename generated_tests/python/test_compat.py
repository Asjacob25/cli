import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

import pytest
import sys
from ssl import SSLContext
import importlib.metadata
import importlib_metadata
from unittest.mock import patch, MagicMock

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

@pytest.fixture(scope="module")
def ssl_context():
    return SSLContext()

def test_is_windows():
    assert isinstance(is_windows, bool)

def test_is_frozen():
    assert isinstance(is_frozen, bool)

def test_min_supported_py_version():
    assert MIN_SUPPORTED_PY_VERSION <= sys.version_info

def test_max_supported_py_version():
    assert MAX_SUPPORTED_PY_VERSION >= sys.version_info

@pytest.mark.skipif(sys.version_info < (3, 8), reason="cached_property exists in Python 3.8+")
def test_cached_property_exists():
    assert hasattr(cached_property, '__get__')

def test_cached_property_functionality():
    class Test:
        def __init__(self, value):
            self._value = value
        
        @cached_property
        def value(self):
            return self._value
    
    t = Test(5)
    assert t.value == 5

def test_find_entry_points_normal_case():
    entry_points = MagicMock()
    entry_points.select = MagicMock(return_value=["entry1", "entry2"])
    result = find_entry_points(entry_points, "group")
    assert len(result) == 2

@pytest.mark.skipif(sys.version_info < (3, 10), reason="select method available in Python 3.10+ or importlib_metadata >= 3.9.0")
def test_find_entry_points_select_method():
    with patch("importlib.metadata.EntryPoint.select", return_value=["entry1"], create=True):
        entry_points = importlib.metadata.entry_points()
        result = list(find_entry_points(entry_points, "console_scripts"))
        assert len(result) >= 1  # assuming there's at least one console_script entry point in the environment

@pytest.mark.parametrize("version_info,expected_import", [
    ((3, 8), "importlib.metadata"),
    ((3, 7), "importlib_metadata"),
])
def test_importlib_metadata_import(version_info, expected_import):
    with patch("sys.version_info", version_info):
        if version_info >= (3, 8):
            import importlib.metadata as importlib_metadata
        else:
            import importlib_metadata
        assert importlib_metadata.__name__ in expected_import

def test_get_dist_name_found(monkeypatch):
    entry_point = MagicMock()
    entry_point.dist = MagicMock()
    entry_point.dist.name = "package_name"
    assert get_dist_name(entry_point) == "package_name"

def test_get_dist_name_not_found(monkeypatch):
    entry_point = MagicMock()
    entry_point.dist = None
    monkeypatch.setattr(importlib_metadata, "metadata", MagicMock(side_effect=importlib_metadata.PackageNotFoundError))
    assert get_dist_name(entry_point) is None

def test_ensure_default_certs_loaded_not_loaded(ssl_context):
    ssl_context.load_default_certs = MagicMock()
    ssl_context.get_ca_certs = MagicMock(return_value=[])
    ensure_default_certs_loaded(ssl_context)
    ssl_context.load_default_certs.assert_called_once()

def test_ensure_default_certs_loaded_already_loaded(ssl_context):
    ssl_context.load_default_certs = MagicMock()
    ssl_context.get_ca_certs = MagicMock(return_value=["cert"])
    ensure_default_certs_loaded(ssl_context)
    ssl_context.load_default_certs.assert_not_called()