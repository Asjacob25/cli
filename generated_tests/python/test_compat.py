import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

import sys
import pytest
from unittest.mock import Mock, patch, MagicMock
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
    entry_point = Mock(spec=importlib_metadata.EntryPoint)
    entry_point.value = "module.submodule:func"
    entry_point.pattern = re.compile(r"(?P<module>\w+)")
    return entry_point


@pytest.fixture
def mock_ssl_context():
    return Mock(spec=SSLContext)


class TestCompatModule:
    @pytest.mark.parametrize("platform, expected", [
        ("win32", True),
        ("WIN32", True),
        ("linux", False),
        ("darwin", False),
    ])
    def test_is_windows(self, platform, expected):
        """
        Test the is_windows variable for different platforms.
        """
        with patch('httpie.compat.sys.platform', platform):
            from httpie import compat
            assert compat.is_windows == expected

    @pytest.mark.parametrize("frozen, expected", [
        (True, True),
        (False, False),
        (None, False),
    ])
    def test_is_frozen(self, frozen, expected):
        """
        Test the is_frozen variable based on sys.frozen attribute.
        """
        with patch.dict('httpie.compat.sys.__dict__', {'frozen': frozen}):
            from httpie import compat
            assert compat.is_frozen == expected

    @pytest.mark.parametrize("entry_points, group, expected", [
        (
            Mock(select=Mock(return_value=['ep1', 'ep2']),
                 get=Mock(return_value=['ep3']),
                 __dict__={'select': Mock()}),
            "group1",
            ['ep1', 'ep2']
        ),
        (
            Mock(select=AttributeError(),
                 get=Mock(return_value={'group1': ['ep1', 'ep2']})),
            "group1",
            {'ep1', 'ep2'}
        ),
        (
            Mock(select=Mock(return_value=[]),
                 get=Mock(return_value={'group2': ['ep3']})),
            "group1",
            []
        ),
        (
            Mock(select=Mock(return_value=None),
                 get=Mock(return_value=None)),
            "group1",
            set()
        ),
    ])
    def test_find_entry_points(self, entry_points, group, expected):
        """
        Test the find_entry_points function with various entry_points objects.
        """
        if hasattr(entry_points, 'select'):
            result = find_entry_points(entry_points, group)
            assert result == expected
        else:
            result = find_entry_points(entry_points, group)
            assert result == expected

    def test_find_entry_points_no_group(self):
        """
        Test find_entry_points when the group does not exist.
        """
        entry_points = Mock(select=Mock(return_value=[]), get=Mock(return_value={}))
        result = find_entry_points(entry_points, "nonexistent_group")
        assert result == set()

    def test_get_dist_name_with_dist(self, mock_entry_point):
        """
        Test get_dist_name when entry_point has a dist attribute.
        """
        mock_dist = Mock()
        mock_dist.name = "mocked_dist"
        mock_entry_point.dist = mock_dist
        dist_name = get_dist_name(mock_entry_point)
        assert dist_name == "mocked_dist"

    def test_get_dist_name_without_dist_package_found(self, mock_entry_point):
        """
        Test get_dist_name when entry_point does not have dist and package is found.
        """
        mock_entry_point.dist = None
        mock_entry_point.pattern = re.compile(r"(?P<module>\w+)")
        mock_metadata = Mock()
        mock_metadata.get.return_value = "MetadataName"
        with patch('httpie.compat.importlib_metadata.metadata', return_value=mock_metadata):
            dist_name = get_dist_name(mock_entry_point)
            assert dist_name == "MetadataName"

    def test_get_dist_name_without_dist_package_not_found(self, mock_entry_point):
        """
        Test get_dist_name when entry_point does not have dist and package is not found.
        """
        mock_entry_point.dist = None
        mock_entry_point.pattern = re.compile(r"(?P<module>\w+)")
        with patch('httpie.compat.importlib_metadata.metadata', side_effect=importlib_metadata.PackageNotFoundError):
            dist_name = get_dist_name(mock_entry_point)
            assert dist_name is None

    def test_get_dist_name_no_module_match(self, mock_entry_point):
        """
        Test get_dist_name when module pattern does not match.
        """
        mock_entry_point.dist = None
        mock_entry_point.pattern = re.compile(r"NoMatchPattern")
        dist_name = get_dist_name(mock_entry_point)
        assert dist_name is None

    def test_ensure_default_certs_loaded_with_load(self, mock_ssl_context):
        """
        Test ensure_default_certs_loaded when ssl_context has load_default_certs
        and get_ca_certs returns empty.
        """
        mock_ssl_context.get_ca_certs.return_value = []
        ensure_default_certs_loaded(mock_ssl_context)
        mock_ssl_context.load_default_certs.assert_called_once()

    def test_ensure_default_certs_loaded_with_ca_certs(self, mock_ssl_context):
        """
        Test ensure_default_certs_loaded when ssl_context already has CA certs.
        """
        mock_ssl_context.get_ca_certs.return_value = ['cert1']
        ensure_default_certs_loaded(mock_ssl_context)
        mock_ssl_context.load_default_certs.assert_not_called()

    def test_ensure_default_certs_loaded_no_load(self, mock_ssl_context):
        """
        Test ensure_default_certs_loaded when ssl_context does not have load_default_certs.
        """
        mock_ssl_context.get_ca_certs.return_value = []
        del mock_ssl_context.load_default_certs
        ensure_default_certs_loaded(mock_ssl_context)
        # Should not raise and load_default_certs is not called
        assert not hasattr(mock_ssl_context, 'load_default_certs')

    def test_cached_property_decorator(self):
        """
        Test the cached_property decorator functionality.
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

    @pytest.mark.skipif(sys.version_info >= (3, 8), reason="cached_property is from functools in Python 3.8+")
    def test_custom_cached_property(self):
        """
        Test the custom cached_property implementation for Python versions <3.8.
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

    def test_cached_property_set_name_conflict(self):
        """
        Test cached_property when setting the same property name to different functions.
        """
        class TestClass:
            @cached_property
            def value1(self):
                return 1

            @cached_property
            def value2(self):
                return 2

        with pytest.raises(TypeError) as excinfo:
            class ConflictingTestClass:
                @cached_property
                def value(self):
                    return 1

                @cached_property
                def value(self):
                    return 2

        assert "Cannot assign the same cached_property to two different names" in str(excinfo.value)