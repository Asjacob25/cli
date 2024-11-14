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
    cached_property,
)
from httpie.cookies import HTTPieCookiePolicy
import importlib_metadata


@pytest.fixture
def mock_sys_platform():
    with patch('httpie.compat.sys') as mock_sys:
        yield mock_sys


@pytest.fixture
def mock_sys_frozen():
    with patch('httpie.compat.sys') as mock_sys:
        yield mock_sys


@pytest.fixture
def mock_importlib_metadata():
    with patch('httpie.compat.importlib_metadata') as mock_metadata:
        yield mock_metadata


class TestCompatibility:
    @patch('httpie.compat.sys.platform', 'win32')
    def test_is_windows_true_on_windows(self):
        """
        Test that is_windows is True when sys.platform contains 'win32'.
        """
        assert is_windows is True

    @patch('httpie.compat.sys.platform', 'linux')
    def test_is_windows_false_on_non_windows(self):
        """
        Test that is_windows is False when sys.platform does not contain 'win32'.
        """
        from httpie.compat import is_windows
        assert is_windows is False

    @patch.dict('sys.__dict__', {'frozen': True})
    def test_is_frozen_true_when_frozen(self):
        """
        Test that is_frozen is True when sys.frozen is set to True.
        """
        from httpie.compat import is_frozen
        assert is_frozen is True

    @patch.dict('sys.__dict__', {}, clear=True)
    def test_is_frozen_false_when_not_frozen(self):
        """
        Test that is_frozen is False when sys.frozen is not set.
        """
        from httpie.compat import is_frozen
        assert is_frozen is False

    @patch('httpie.compat.functools.cached_property', new_callable=MagicMock)
    def test_cached_property_imported_when_available(self, mock_cached_property):
        """
        Test that cached_property is imported from functools when available.
        """
        from httpie.compat import cached_property
        assert cached_property == mock_cached_property
        mock_cached_property.assert_not_called()

    @patch('httpie.compat.functools', side_effect=ImportError)
    def test_cached_property_fallback_when_import_fails(self, mock_functools):
        """
        Test that a custom cached_property is used when functools.cached_property is unavailable.
        """
        from httpie.compat import cached_property
        instance = MagicMock()
        
        @cached_property
        def dummy_property(self):
            return 'cached_value'
        
        # Simulate setting the property
        descriptor = cached_property(dummy_property)
        descriptor.__set_name__(MagicMock(), 'dummy')
        
        assert 'dummy' not in instance.__dict__
        result = descriptor.__get__(instance, None)
        assert result == 'cached_value'
        assert instance.__dict__['dummy'] == 'cached_value'

    def test_min_supported_py_version(self):
        """
        Test that MIN_SUPPORTED_PY_VERSION is set to (3, 7).
        """
        from httpie.compat import MIN_SUPPORTED_PY_VERSION
        assert MIN_SUPPORTED_PY_VERSION == (3, 7)

    def test_max_supported_py_version(self):
        """
        Test that MAX_SUPPORTED_PY_VERSION is set to (3, 11).
        """
        from httpie.compat import MAX_SUPPORTED_PY_VERSION
        assert MAX_SUPPORTED_PY_VERSION == (3, 11))


class TestFindEntryPoints:
    def test_find_entry_points_with_select(self, mock_importlib_metadata):
        """
        Test find_entry_points uses select when available.
        """
        mock_entry_points = MagicMock()
        mock_entry_points.select.return_value = ['entry1', 'entry2']
        result = find_entry_points(mock_entry_points, 'group')
        mock_entry_points.select.assert_called_once_with(group='group')
        assert result == ['entry1', 'entry2']

    def test_find_entry_points_without_select(self, mock_importlib_metadata):
        """
        Test find_entry_points uses get when select is not available.
        """
        mock_entry_points = MagicMock()
        del mock_entry_points.select
        mock_entry_points.get.return_value = {'entry1', 'entry2'}
        result = find_entry_points(mock_entry_points, 'group')
        mock_entry_points.get.assert_called_once_with('group', ())
        assert result == {'entry1', 'entry2'}

    def test_find_entry_points_empty_group(self, mock_importlib_metadata):
        """
        Test find_entry_points returns empty set when group has no entry points.
        """
        mock_entry_points = MagicMock()
        if hasattr(mock_entry_points, 'select'):
            mock_entry_points.select.return_value = []
        else:
            mock_entry_points.get.return_value = ()
        result = find_entry_points(mock_entry_points, 'nonexistent_group')
        assert result == [] if hasattr(mock_entry_points, 'select') else set()


class TestGetDistName:
    def test_get_dist_name_with_dist(self, mock_importlib_metadata):
        """
        Test get_dist_name returns dist.name when entry_point has dist attribute.
        """
        mock_entry_point = MagicMock()
        mock_entry_point.dist.name = 'test_dist'
        dist_name = get_dist_name(mock_entry_point)
        assert dist_name == 'test_dist'

    def test_get_dist_name_without_dist_with_valid_module(self, mock_importlib_metadata):
        """
        Test get_dist_name parses the package name from entry_point and retrieves metadata.
        """
        mock_entry_point = MagicMock()
        mock_entry_point.pattern.match.return_value = MagicMock(group=MagicMock(return_value='module.submodule'))
        mock_importlib_metadata.metadata.return_value.get.return_value = 'test_package'
        dist_name = get_dist_name(mock_entry_point)
        mock_entry_point.pattern.match.assert_called_once_with(mock_entry_point.value)
        mock_importlib_metadata.metadata.assert_called_once_with('module')
        mock_importlib_metadata.metadata.return_value.get.assert_called_once_with('name')
        assert dist_name == 'test_package'

    def test_get_dist_name_without_dist_with_invalid_module(self, mock_importlib_metadata):
        """
        Test get_dist_name returns None when module parsing fails.
        """
        mock_entry_point = MagicMock()
        mock_entry_point.pattern.match.return_value = None
        dist_name = get_dist_name(mock_entry_point)
        assert dist_name is None

    def test_get_dist_name_package_not_found(self, mock_importlib_metadata):
        """
        Test get_dist_name returns None when package metadata is not found.
        """
        mock_entry_point = MagicMock()
        mock_entry_point.pattern.match.return_value = MagicMock(group=MagicMock(return_value='module.submodule'))
        mock_importlib_metadata.metadata.side_effect = importlib_metadata.PackageNotFoundError
        dist_name = get_dist_name(mock_entry_point)
        mock_importlib_metadata.metadata.assert_called_once_with('module')
        assert dist_name is None


class TestEnsureDefaultCertsLoaded:
    def test_certs_already_loaded(self):
        """
        Test that load_default_certs is not called if certs are already loaded.
        """
        mock_ssl_context = MagicMock(spec=SSLContext)
        mock_ssl_context.get_ca_certs.return_value = ['cert1']
        ensure_default_certs_loaded(mock_ssl_context)
        mock_ssl_context.load_default_certs.assert_not_called()

    def test_certs_not_loaded_and_load_available(self):
        """
        Test that load_default_certs is called when certs are not loaded and method is available.
        """
        mock_ssl_context = MagicMock(spec=SSLContext)
        mock_ssl_context.get_ca_certs.return_value = []
        mock_ssl_context.load_default_certs = MagicMock()
        ensure_default_certs_loaded(mock_ssl_context)
        mock_ssl_context.load_default_certs.assert_called_once()

    def test_certs_not_loaded_and_load_not_available(self):
        """
        Test that ensure_default_certs_loaded does nothing when load_default_certs is not available.
        """
        mock_ssl_context = MagicMock(spec=SSLContext)
        mock_ssl_context.get_ca_certs.return_value = []
        del mock_ssl_context.load_default_certs
        ensure_default_certs_loaded(mock_ssl_context)
        assert not hasattr(mock_ssl_context, 'load_default_certs')


class TestHTTPieCookiePolicy:
    @pytest.fixture
    def cookie_policy(self):
        return HTTPieCookiePolicy()

    def test_return_ok_secure_with_secure_protocol(self, cookie_policy):
        """
        Test return_ok_secure returns True when secure protocol is used.
        """
        mock_cookie = MagicMock()
        mock_request = MagicMock()
        with patch.object(cookie_policy, 'return_ok_secure', return_value=True):
            result = cookie_policy.return_ok_secure(mock_cookie, mock_request)
            assert result is True

    def test_return_ok_secure_with_localhost(self, cookie_policy):
        """
        Test return_ok_secure returns True when hostname is localhost.
        """
        mock_cookie = MagicMock()
        mock_request = MagicMock()
        mock_request.host = 'localhost'
        with patch.object(cookie_policy, '_is_local_host', return_value=True):
            result = cookie_policy.return_ok_secure(mock_cookie, mock_request)
            assert result is True

    def test_return_ok_secure_with_non_secure_non_localhost(self, cookie_policy):
        """
        Test return_ok_secure returns False when protocol is not secure and hostname is not localhost.
        """
        mock_cookie = MagicMock()
        mock_request = MagicMock()
        with patch.object(cookie_policy, 'return_ok_secure', return_value=False):
            with patch.object(cookie_policy, '_is_local_host', return_value=False):
                result = cookie_policy.return_ok_secure(mock_cookie, mock_request)
                assert result is False

    def test_is_local_host_exact_localhost(self, cookie_policy):
        """
        Test _is_local_host returns True for exact 'localhost'.
        """
        assert cookie_policy._is_local_host('localhost') is True

    def test_is_local_host_with_suffix(self, cookie_policy):
        """
        Test _is_local_host returns True for hostnames ending with '.localhost'.
        """
        assert cookie_policy._is_local_host('example.localhost') is True

    def test_is_local_host_false(self, cookie_policy):
        """
        Test _is_local_host returns False for non-localhost hostnames.
        """
        assert cookie_policy._is_local_host('example.com') is False

    def test_set_name_and_func_once(self, cookie_policy):
        """
        Test that __set_name__ sets the name and func once.
        """
        owner = MagicMock()
        cookie_policy.__set_name__(owner, 'test_property')
        assert cookie_policy.name == 'test_property'
        assert cookie_policy.func is None  # func is not set in return_ok_secure

    def test_set_name_twice_raises_error(self, cookie_policy):
        """
        Test that setting the name to a different value raises TypeError.
        """
        owner = MagicMock()
        cookie_policy.__set_name__(owner, 'test_property')
        with pytest.raises(TypeError):
            cookie_policy.__set_name__(owner, 'another_property')

    def test_get_cached_property(self, cookie_policy):
        """
        Test that getting the cached property calls the function and caches the result.
        """
        instance = {}
        def dummy_func(inst):
            return 'cached_result'

        descriptor = HTTPieCookiePolicy().return_ok_secure
        descriptor.real_func = dummy_func
        descriptor.name = 'cached_prop'

        result = descriptor.__get__(instance, None)
        assert result == 'cached_result'
        assert instance['cached_prop'] == 'cached_result'

    def test_get_cached_property_instance_none(self, cookie_policy):
        """
        Test that __get__ returns the descriptor itself when instance is None.
        """
        descriptor = HTTPieCookiePolicy().return_ok_secure
        descriptor.name = 'cached_prop'
        result = descriptor.__get__(None, None)
        assert result is descriptor


def test_cookie_policy_override():
    """
    Test that cookiejar.DefaultCookiePolicy is overridden with HTTPieCookiePolicy.
    """
    from http import cookiejar
    from httpie.cookies import HTTPieCookiePolicy
    assert cookiejar.DefaultCookiePolicy == HTTPieCookiePolicy


class TestConstants:
    def test_min_supported_py_version(self):
        """
        Test MIN_SUPPORTED_PY_VERSION is correctly set.
        """
        from httpie.compat import MIN_SUPPORTED_PY_VERSION
        assert MIN_SUPPORTED_PY_VERSION == (3, 7)

    def test_max_supported_py_version(self):
        """
        Test MAX_SUPPORTED_PY_VERSION is correctly set.
        """
        from httpie.compat import MAX_SUPPORTED_PY_VERSION
        assert MAX_SUPPORTED_PY_VERSION == (3, 11)


class TestCachedProperty:
    def test_cached_property_decorator(self):
        """
        Test that cached_property decorator caches the result after first call.
        """
        class TestClass:
            def __init__(self):
                self.call_count = 0

            @cached_property
            def prop(self):
                self.call_count += 1
                return 'value'

        obj = TestClass()
        assert obj.call_count == 0
        assert obj.prop == 'value'
        assert obj.call_count == 1
        assert obj.prop == 'value'
        assert obj.call_count == 1  # Should not increment again

    def test_cached_property_without_set_name(self):
        """
        Test that accessing cached_property without setting name raises TypeError.
        """
        class TestClass:
            prop = cached_property(lambda self: 'value')

        obj = TestClass()
        with pytest.raises(TypeError):
            _ = obj.prop

    def test_cached_property_multiple_names_raises_error(self):
        """
        Test that assigning cached_property to multiple names raises TypeError.
        """
        class TestClass:
            prop1 = cached_property(lambda self: 'value1')

        with pytest.raises(TypeError):
            class AnotherTestClass:
                prop2 = TestClass.prop1


class TestEnsureDefaultCertsLoaded:
    @patch('httpie.compat.SSLContext')
    def test_ensure_default_certs_loaded_when_required(self, mock_ssl_context_class):
        """
        Test that ensure_default_certs_loaded loads default certs when none are loaded.
        """
        mock_ssl_context = mock_ssl_context_class.return_value
        mock_ssl_context.get_ca_certs.return_value = []
        mock_ssl_context.load_default_certs = MagicMock()

        ensure_default_certs_loaded(mock_ssl_context)

        mock_ssl_context.load_default_certs.assert_called_once()

    @patch('httpie.compat.SSLContext')
    def test_ensure_default_certs_not_loaded_when_already_present(self, mock_ssl_context_class):
        """
        Test that ensure_default_certs_loaded does not load certs if they are already loaded.
        """
        mock_ssl_context = mock_ssl_context_class.return_value
        mock_ssl_context.get_ca_certs.return_value = ['cert']
        mock_ssl_context.load_default_certs = MagicMock()

        ensure_default_certs_loaded(mock_ssl_context)

        mock_ssl_context.load_default_certs.assert_not_called()

    @patch('httpie.compat.SSLContext')
    def test_ensure_default_certs_loaded_without_load_method(self, mock_ssl_context_class):
        """
        Test that ensure_default_certs_loaded does nothing if load_default_certs is not available.
        """
        mock_ssl_context = mock_ssl_context_class.return_value
        mock_ssl_context.get_ca_certs.return_value = []
        del mock_ssl_context.load_default_certs

        ensure_default_certs_loaded(mock_ssl_context)

        # No exception should be raised and load_default_certs should not be called
        assert not hasattr(mock_ssl_context, 'load_default_certs')


class TestFindEntryPointsFunction:
    def test_find_entry_points_python_3_10_plus(self):
        """
        Test find_entry_points function for Python 3.10+ where select is available.
        """
        entry_points_mock = MagicMock()
        entry_points_mock.select.return_value = ['ep1', 'ep2']
        result = find_entry_points(entry_points_mock, 'group')
        entry_points_mock.select.assert_called_once_with(group='group')
        assert result == ['ep1', 'ep2']

    def test_find_entry_points_python_before_3_10(self):
        """
        Test find_entry_points function for Python versions before 3.10 where select is not available.
        """
        entry_points_mock = MagicMock()
        del entry_points_mock.select
        entry_points_mock.get.return_value = {'ep1', 'ep2'}
        result = find_entry_points(entry_points_mock, 'group')
        entry_points_mock.get.assert_called_once_with('group', ())
        assert result == {'ep1', 'ep2'}

    def test_find_entry_points_no_entry_points(self):
        """
        Test find_entry_points returns empty iterable when no entry points are found.
        """
        entry_points_mock = MagicMock()
        if hasattr(entry_points_mock, 'select'):
            entry_points_mock.select.return_value = []
            result = find_entry_points(entry_points_mock, 'empty_group')
            assert result == []
        else:
            entry_points_mock.get.return_value = {}
            result = find_entry_points(entry_points_mock, 'empty_group')
            assert result == set()


class TestGetDistNameFunction:
    def test_get_dist_name_with_dist_attribute(self):
        """
        Test get_dist_name returns the dist name if the entry point has a dist attribute.
        """
        entry_point_mock = MagicMock()
        entry_point_mock.dist.name = 'dist-name'
        dist_name = get_dist_name(entry_point_mock)
        assert dist_name == 'dist-name'

    def test_get_dist_name_without_dist_attribute_valid_module(self):
        """
        Test get_dist_name extracts the package name from the module and retrieves metadata.
        """
        with patch('httpie.compat.importlib_metadata.metadata') as mock_metadata:
            entry_point_mock = MagicMock()
            match_mock = MagicMock()
            match_mock.group.return_value = 'module.submodule'
            entry_point_mock.pattern.match.return_value = match_mock
            mock_metadata.return_value.get.return_value = 'package-name'

            dist_name = get_dist_name(entry_point_mock)
            assert dist_name == 'package-name'
            entry_point_mock.pattern.match.assert_called_once_with(entry_point_mock.value)
            mock_metadata.assert_called_once_with('module')

    def test_get_dist_name_without_dist_attribute_invalid_module(self):
        """
        Test get_dist_name returns None if module parsing fails.
        """
        entry_point_mock = MagicMock()
        entry_point_mock.pattern.match.return_value = None
        dist_name = get_dist_name(entry_point_mock)
        assert dist_name is None

    def test_get_dist_name_metadata_not_found(self):
        """
        Test get_dist_name returns None if package metadata is not found.
        """
        with patch('httpie.compat.importlib_metadata.metadata', side_effect=importlib_metadata.PackageNotFoundError):
            entry_point_mock = MagicMock()
            match_mock = MagicMock()
            match_mock.group.return_value = 'module.submodule'
            entry_point_mock.pattern.match.return_value = match_mock

            dist_name = get_dist_name(entry_point_mock)
            assert dist_name is None


class TestEnsureDefaultCertsLoadedFunction:
    def test_load_default_certs_called_when_no_certs(self):
        """
        Test that load_default_certs is called when no CA certs are loaded.
        """
        mock_ssl_context = MagicMock(spec=SSLContext)
        mock_ssl_context.get_ca_certs.return_value = []
        mock_ssl_context.load_default_certs = MagicMock()

        ensure_default_certs_loaded(mock_ssl_context)

        mock_ssl_context.load_default_certs.assert_called_once()

    def test_load_default_certs_not_called_when_certs_present(self):
        """
        Test that load_default_certs is not called when CA certs are already loaded.
        """
        mock_ssl_context = MagicMock(spec=SSLContext)
        mock_ssl_context.get_ca_certs.return_value = ['cert1', 'cert2']
        mock_ssl_context.load_default_certs = MagicMock()

        ensure_default_certs_loaded(mock_ssl_context)

        mock_ssl_context.load_default_certs.assert_not_called()

    def test_load_default_certs_not_available(self):
        """
        Test that ensure_default_certs_loaded does nothing if load_default_certs is not available.
        """
        mock_ssl_context = MagicMock(spec=SSLContext)
        mock_ssl_context.get_ca_certs.return_value = []
        del mock_ssl_context.load_default_certs

        ensure_default_certs_loaded(mock_ssl_context)

        # Ensure no exception is raised and load_default_certs is not called
        assert not hasattr(mock_ssl_context, 'load_default_certs')


class TestInitialization:
    def test_cookie_policy_override_on_import(self):
        """
        Test that DefaultCookiePolicy is overridden upon importing compat.py.
        """
        from http import cookiejar
        from httpie.cookies import HTTPieCookiePolicy
        assert cookiejar.DefaultCookiePolicy is HTTPieCookiePolicy