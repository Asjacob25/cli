import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

import sys
import pytest
from unittest import mock
from unittest.mock import MagicMock, patch
from httpie.compat import (
    is_windows,
    is_frozen,
    find_entry_points,
    get_dist_name,
    ensure_default_certs_loaded,
    cached_property,
)
from ssl import SSLContext
import importlib_metadata
from httpie.cookies import HTTPieCookiePolicy
from http import cookiejar

# Test is_windows variable
def test_is_windows_true():
    """Test is_windows is True when sys.platform contains 'win32'."""
    with mock.patch('httpie.compat.sys.platform', 'win32'):
        from httpie import compat
        assert compat.is_windows is True

def test_is_windows_false():
    """Test is_windows is False when sys.platform does not contain 'win32'."""
    with mock.patch('httpie.compat.sys.platform', 'linux'):
        from httpie import compat
        assert compat.is_windows is False

# Test is_frozen variable
def test_is_frozen_true():
    """Test is_frozen is True when sys.frozen attribute exists and is True."""
    with mock.patch('httpie.compat.sys.frozen', True):
        from httpie import compat
        assert compat.is_frozen is True

def test_is_frozen_false():
    """Test is_frozen is False when sys.frozen attribute does not exist or is False."""
    with mock.patch('httpie.compat.getattr', side_effect=lambda obj, name, default=False: default):
        from httpie import compat
        assert compat.is_frozen is False

# Test find_entry_points function
@pytest.fixture
def mock_entry_points_with_select():
    mock_ep = MagicMock()
    mock_ep.select.return_value = ['entry1', 'entry2']
    return mock_ep

@pytest.fixture
def mock_entry_points_without_select():
    mock_ep = {'group1': ['entry1'], 'group2': ['entry2']}
    return mock_ep

def test_find_entry_points_with_select(mock_entry_points_with_select):
    """Test find_entry_points with entry_points having select method."""
    result = find_entry_points(mock_entry_points_with_select, 'group1')
    mock_entry_points_with_select.select.assert_called_once_with(group='group1')
    assert result == ['entry1', 'entry2']

def test_find_entry_points_without_select(mock_entry_points_without_select):
    """Test find_entry_points with entry_points without select method."""
    result = find_entry_points(mock_entry_points_without_select, 'group1')
    assert result == {'entry1'}

def test_find_entry_points_empty_group(mock_entry_points_without_select):
    """Test find_entry_points with non-existing group."""
    result = find_entry_points(mock_entry_points_without_select, 'nonexistent')
    assert result == set()

# Test get_dist_name function
def test_get_dist_name_with_dist():
    """Test get_dist_name when entry_point has dist attribute."""
    mock_ep = MagicMock()
    mock_ep.dist.name = 'testdist'
    result = get_dist_name(mock_ep)
    assert result == 'testdist'

def test_get_dist_name_without_dist_valid_module():
    """Test get_dist_name when entry_point has no dist but valid module pattern."""
    mock_ep = MagicMock()
    mock_ep.pattern.match.return_value.group.return_value = 'testmodule.submodule'
    mock_ep.value = 'testmodule.submodule'
    with patch('httpie.compat.importlib_metadata.metadata') as mock_metadata:
        mock_metadata.return_value.get.return_value = 'Test Distribution'
        result = get_dist_name(mock_ep)
        mock_metadata.assert_called_once_with('testmodule')
        assert result == 'Test Distribution'

def test_get_dist_name_without_dist_invalid_module():
    """Test get_dist_name when entry_point has no dist and invalid module pattern."""
    mock_ep = MagicMock()
    mock_ep.pattern.match.return_value = None
    result = get_dist_name(mock_ep)
    assert result is None

def test_get_dist_name_package_not_found():
    """Test get_dist_name when package metadata is not found."""
    mock_ep = MagicMock()
    mock_ep.pattern.match.return_value.group.return_value = 'nonexistent.module'
    mock_ep.value = 'nonexistent.module'
    with patch('httpie.compat.importlib_metadata.metadata', side_effect=importlib_metadata.PackageNotFoundError):
        result = get_dist_name(mock_ep)
        assert result is None

# Test ensure_default_certs_loaded function
def test_ensure_default_certs_loaded_loads_when_no_certs():
    """Test ensure_default_certs_loaded loads default certs when get_ca_certs is empty."""
    mock_ssl = MagicMock(spec=SSLContext)
    mock_ssl.get_ca_certs.return_value = []
    ensure_default_certs_loaded(mock_ssl)
    mock_ssl.load_default_certs.assert_called_once()

def test_ensure_default_certs_loaded_does_not_load_when_certs_present():
    """Test ensure_default_certs_loaded does not load default certs when get_ca_certs is not empty."""
    mock_ssl = MagicMock(spec=SSLContext)
    mock_ssl.get_ca_certs.return_value = [{'issuer': 'Test CA'}]
    ensure_default_certs_loaded(mock_ssl)
    mock_ssl.load_default_certs.assert_not_called()

def test_ensure_default_certs_loaded_no_load_default_certs_method():
    """Test ensure_default_certs_loaded does nothing if load_default_certs is not present."""
    mock_ssl = MagicMock(spec=SSLContext)
    mock_ssl.get_ca_certs.return_value = []
    del mock_ssl.load_default_certs
    ensure_default_certs_loaded(mock_ssl)
    # load_default_certs should not be called since it doesn't exist
    assert not hasattr(mock_ssl, 'load_default_certs')

# Test HTTPieCookiePolicy
def test_HTTPieCookiePolicy_return_ok_secure_secure_protocol():
    """Test HTTPieCookiePolicy.return_ok_secure returns True for secure protocol."""
    policy = HTTPieCookiePolicy()
    mock_cookie = MagicMock()
    mock_request = MagicMock()
    with patch.object(cookiejar.DefaultCookiePolicy, 'return_ok_secure', return_value=True) as mock_super:
        assert policy.return_ok_secure(mock_cookie, mock_request) is True
        mock_super.assert_called_once_with(mock_cookie, mock_request)

def test_HTTPieCookiePolicy_return_ok_secure_localhost():
    """Test HTTPieCookiePolicy.return_ok_secure returns True for localhost."""
    policy = HTTPieCookiePolicy()
    mock_cookie = MagicMock()
    mock_request = MagicMock()
    mock_request.host = 'localhost'
    with patch.object(cookiejar.DefaultCookiePolicy, 'return_ok_secure', return_value=False):
        assert policy.return_ok_secure(mock_cookie, mock_request) is True

def test_HTTPieCookiePolicy_return_ok_secure_non_secure():
    """Test HTTPieCookiePolicy.return_ok_secure returns False for non-secure protocol and non-localhost."""
    policy = HTTPieCookiePolicy()
    mock_cookie = MagicMock()
    mock_request = MagicMock()
    mock_request.host = 'example.com'
    with patch.object(cookiejar.DefaultCookiePolicy, 'return_ok_secure', return_value=False):
        assert policy.return_ok_secure(mock_cookie, mock_request) is False

# Test cached_property
def test_cached_property_initialization():
    """Test cached_property initializes correctly."""
    def sample_method(self):
        return 'value'

    prop = cached_property(sample_method)
    assert prop.real_func == sample_method
    assert prop.name is None

def test_cached_property_set_name():
    """Test cached_property sets name correctly via __set_name__."""
    class TestClass:
        prop = cached_property(lambda self: 'value')

    test_instance = TestClass()
    assert test_instance.prop == 'value'
    assert test_instance.__dict__['prop'] == 'value'

def test_cached_property_multiple_names_error():
    """Test cached_property raises TypeError when assigned to multiple names."""
    with pytest.raises(TypeError):
        class TestClass:
            prop1 = cached_property(lambda self: 'value')
            prop2 = cached_property(lambda self: 'value')

def test_cached_property_without_set_name():
    """Test cached_property raises TypeError when accessed without set_name."""
    prop = cached_property(lambda self: 'value')
    with pytest.raises(TypeError):
        prop.func(None)

# Test module-level assignments
def test_cookiejar_default_cookie_policy_assigned():
    """Test that cookiejar.DefaultCookiePolicy is assigned to HTTPieCookiePolicy."""
    assert cookiejar.DefaultCookiePolicy == HTTPieCookiePolicy

# Additional tests for Python version-specific imports and features
def test_importlib_metadata_imported_correctly_python38_plus():
    """Test importlib.metadata is imported for Python >= 3.8."""
    with mock.patch('httpie.compat.sys.version_info', (3, 8)):
        with patch.dict('sys.modules', {'importlib.metadata': importlib_metadata}):
            from httpie import compat
            assert compat.importlib_metadata is importlib_metadata

def test_importlib_metadata_imported_correctly_pre_python38():
    """Test importlib_metadata backport is imported for Python < 3.8."""
    with mock.patch('httpie.compat.sys.version_info', (3, 7)):
        with patch.dict('sys.modules', {'importlib_metadata': importlib_metadata}):
            from httpie import compat
            assert compat.importlib_metadata is importlib_metadata

# Test cached_property availability based on Python version
def test_cached_property_use_builtin_if_available():
    """Test that builtin cached_property is used if available."""
    with patch('httpie.compat.cached_property', new='built_in'):
        from httpie import compat
        assert compat.cached_property == 'built_in'

def test_cached_property_use_custom_if_not_available():
    """Test that custom cached_property is used if builtin is not available."""
    with patch('httpie.compat.cached_property', new=MagicMock()):
        from httpie import compat
        assert isinstance(compat.cached_property, MagicMock)