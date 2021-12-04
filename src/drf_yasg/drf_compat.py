import warnings
from collections import OrderedDict, Counter
from importlib import import_module
from urllib import parse

import coreapi
import coreschema
import uritemplate
from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.db import models
from django.forms.forms import pretty_name
from django.http import Http404
from rest_framework import exceptions, serializers
from rest_framework.mixins import RetrieveModelMixin
from rest_framework.request import clone_request
from rest_framework.utils.model_meta import _get_pk
from django.utils.translation import gettext_lazy


def is_api_view(callback):
    """
    Return `True` if the given view callback is a REST framework view/viewset.
    """
    # Avoid import cycle on APIView
    from rest_framework.views import APIView
    cls = getattr(callback, 'cls', None)
    return (cls is not None) and issubclass(cls, APIView)


def endpoint_ordering(endpoint):
    path, method, callback = endpoint
    method_priority = {
        'GET': 0,
        'POST': 1,
        'PUT': 2,
        'PATCH': 3,
        'DELETE': 4
    }.get(method, 5)
    return (method_priority,)


def get_pk_description(model, model_field):
    if isinstance(model_field, models.AutoField):
        value_type = gettext_lazy('unique integer value')
    elif isinstance(model_field, models.UUIDField):
        value_type = gettext_lazy('UUID string')
    else:
        value_type = gettext_lazy('unique value')

    return _('A {value_type} identifying this {name}.').format(
        value_type=value_type,
        name=model._meta.verbose_name,
    )


def action(methods=None, detail=None, url_path=None, url_name=None, **kwargs):
    """
    Mark a ViewSet method as a routable action.

    `@action`-decorated functions will be endowed with a `mapping` property,
    a `MethodMapper` that can be used to add additional method-based behaviors
    on the routed action.

    :param methods: A list of HTTP method names this action responds to.
                    Defaults to GET only.
    :param detail: Required. Determines whether this action applies to
                   instance/detail requests or collection/list requests.
    :param url_path: Define the URL segment for this action. Defaults to the
                     name of the method decorated.
    :param url_name: Define the internal (`reverse`) URL name for this action.
                     Defaults to the name of the method decorated with underscores
                     replaced with dashes.
    :param kwargs: Additional properties to set on the view.  This can be used
                   to override viewset-level *_classes settings, equivalent to
                   how the `@renderer_classes` etc. decorators work for function-
                   based API views.
    """
    methods = ['get'] if (methods is None) else methods
    methods = [method.lower() for method in methods]

    assert detail is not None, (
        "@action() missing required argument: 'detail'"
    )

    # name and suffix are mutually exclusive
    if 'name' in kwargs and 'suffix' in kwargs:
        raise TypeError("`name` and `suffix` are mutually exclusive arguments.")

    def decorator(func):
        func.mapping = MethodMapper(func, methods)

        func.detail = detail
        func.url_path = url_path if url_path else func.__name__
        func.url_name = url_name if url_name else func.__name__.replace('_', '-')

        # These kwargs will end up being passed to `ViewSet.as_view()` within
        # the router, which eventually delegates to Django's CBV `View`,
        # which assigns them as instance attributes for each request.
        func.kwargs = kwargs

        # Set descriptive arguments for viewsets
        if 'name' not in kwargs and 'suffix' not in kwargs:
            func.kwargs['name'] = pretty_name(func.__name__)
        func.kwargs['description'] = func.__doc__ or None

        return func
    return decorator


class MethodMapper(dict):
    """
    Enables mapping HTTP methods to different ViewSet methods for a single,
    logical action.

    Example usage:

        class MyViewSet(ViewSet):

            @action(detail=False)
            def example(self, request, **kwargs):
                ...

            @example.mapping.post
            def create_example(self, request, **kwargs):
                ...
    """

    def __init__(self, action, methods):
        self.action = action
        for method in methods:
            self[method] = self.action.__name__

    def _map(self, method, func):
        assert method not in self, (
            "Method '%s' has already been mapped to '.%s'." % (method, self[method]))
        assert func.__name__ != self.action.__name__, (
            "Method mapping does not behave like the property decorator. You "
            "cannot use the same method name for each mapping declaration.")

        self[method] = func.__name__

        return func

    def get(self, func):
        return self._map('get', func)

    def post(self, func):
        return self._map('post', func)

    def put(self, func):
        return self._map('put', func)

    def patch(self, func):
        return self._map('patch', func)

    def delete(self, func):
        return self._map('delete', func)

    def head(self, func):
        return self._map('head', func)

    def options(self, func):
        return self._map('options', func)

    def trace(self, func):
        return self._map('trace', func)


def common_path(paths):
    split_paths = [path.strip('/').split('/') for path in paths]
    s1 = min(split_paths)
    s2 = max(split_paths)
    common = s1
    for i, c in enumerate(s1):
        if c != s2[i]:
            common = s1[:i]
            break
    return '/' + '/'.join(common)


def is_custom_action(action):
    return action not in {
        'retrieve', 'list', 'create', 'update', 'partial_update', 'destroy'
    }


def distribute_links(obj):
    for key, value in obj.items():
        distribute_links(value)

    for preferred_key, link in obj.links:
        key = obj.get_available_key(preferred_key)
        obj[key] = link


def get_pk_name(model):
    meta = model._meta.concrete_model._meta
    return _get_pk(meta).name


def is_list_view(path, method, view):
    """
    Return True if the given path/method appears to represent a list view.
    """
    if hasattr(view, 'action'):
        # Viewsets have an explicitly defined action, which we can inspect.
        return view.action == 'list'

    if method.lower() != 'get':
        return False
    if isinstance(view, RetrieveModelMixin):
        return False
    path_components = path.strip('/').split('/')
    if path_components and '{' in path_components[-1]:
        return False
    return True


class EndpointEnumerator:
    def __init__(self, patterns=None, urlconf=None, request=None):
        if patterns is None:
            if urlconf is None:
                # Use the default Django URL conf
                urlconf = settings.ROOT_URLCONF

            # Load the given URLconf module
            if isinstance(urlconf, str):
                urls = import_module(urlconf)
            else:
                urls = urlconf
            patterns = urls.urlpatterns
        self.patterns = patterns
        self.request = request

class BaseSchemaGenerator(object):
    endpoint_inspector_cls = EndpointEnumerator

    # 'pk' isn't great as an externally exposed name for an identifier,
    # so by default we prefer to use the actual model field name for schemas.
    # Set by 'SCHEMA_COERCE_PATH_PK'.
    coerce_path_pk = None

    def __init__(self, title=None, url=None, description=None, patterns=None, urlconf=None, version=None):
        if url and not url.endswith('/'):
            url += '/'

        self.coerce_path_pk = True

        self.patterns = patterns
        self.urlconf = urlconf
        self.title = title
        self.description = description
        self.version = version
        self.url = url
        self.endpoints = None

    def _initialise_endpoints(self):
        if self.endpoints is None:
            inspector = self.endpoint_inspector_cls(self.patterns, self.urlconf)
            self.endpoints = inspector.get_api_endpoints()

    def _get_paths_and_endpoints(self, request):
        """
        Generate (path, method, view) given (path, method, callback) for paths.
        """
        paths = []
        view_endpoints = []
        for path, method, callback in self.endpoints:
            view = self.create_view(callback, method, request)
            path = self.coerce_path(path, method, view)
            paths.append(path)
            view_endpoints.append((path, method, view))

        return paths, view_endpoints

    def create_view(self, callback, method, request=None):
        """
        Given a callback, return an actual view instance.
        """
        view = callback.cls(**getattr(callback, 'initkwargs', {}))
        view.args = ()
        view.kwargs = {}
        view.format_kwarg = None
        view.request = None
        view.action_map = getattr(callback, 'actions', None)

        actions = getattr(callback, 'actions', None)
        if actions is not None:
            if method == 'OPTIONS':
                view.action = 'metadata'
            else:
                view.action = actions.get(method.lower())

        if request is not None:
            view.request = clone_request(request, method)

        return view

    def coerce_path(self, path, method, view):
        """
        Coerce {pk} path arguments into the name of the model field,
        where possible. This is cleaner for an external representation.
        (Ie. "this is an identifier", not "this is a database primary key")
        """
        if not self.coerce_path_pk or '{pk}' not in path:
            return path
        model = getattr(getattr(view, 'queryset', None), 'model', None)
        if model:
            field_name = get_pk_name(model)
        else:
            field_name = 'id'
        return path.replace('{pk}', '{%s}' % field_name)

    def get_schema(self, request=None, public=False):
        raise NotImplementedError(".get_schema() must be implemented in subclasses.")

    def has_view_permissions(self, path, method, view):
        """
        Return `True` if the incoming request has the correct view permissions.
        """
        if view.request is None:
            return True

        try:
            view.check_permissions(view.request)
        except (exceptions.APIException, Http404, PermissionDenied):
            return False
        return True
# ----------------------------------


INSERT_INTO_COLLISION_FMT = """
Schema Naming Collision.

coreapi.Link for URL path {value_url} cannot be inserted into schema.
Position conflicts with coreapi.Link for URL path {target_url}.

Attempted to insert link with keys: {keys}.

Adjust URLs to avoid naming collision or override `SchemaGenerator.get_keys()`
to customise schema structure.
"""


class LinkNode(OrderedDict):
    def __init__(self):
        self.links = []
        self.methods_counter = Counter()
        super(LinkNode, self).__init__()

    def get_available_key(self, preferred_key):
        if preferred_key not in self:
            return preferred_key

        while True:
            current_val = self.methods_counter[preferred_key]
            self.methods_counter[preferred_key] += 1

            key = '{}_{}'.format(preferred_key, current_val)
            if key not in self:
                return key

def insert_into(target, keys, value):
    """
    Nested dictionary insertion.

    >>> example = {}
    >>> insert_into(example, ['a', 'b', 'c'], 123)
    >>> example
    LinkNode({'a': LinkNode({'b': LinkNode({'c': LinkNode(links=[123])}}})))
    """
    for key in keys[:-1]:
        if key not in target:
            target[key] = LinkNode()
        target = target[key]

    try:
        target.links.append((keys[-1], value))
    except TypeError:
        msg = INSERT_INTO_COLLISION_FMT.format(
            value_url=value.url,
            target_url=target.url,
            keys=keys
        )
        raise ValueError(msg)


class SchemaGenerator(BaseSchemaGenerator):
    """
    Original CoreAPI version.
    """
    # Map HTTP methods onto actions.
    default_mapping = {
        'get': 'retrieve',
        'post': 'create',
        'put': 'update',
        'patch': 'partial_update',
        'delete': 'destroy',
    }

    # Map the method names we use for viewset actions onto external schema names.
    # These give us names that are more suitable for the external representation.
    # Set by 'SCHEMA_COERCE_METHOD_NAMES'.
    coerce_method_names = None

    def __init__(self, title=None, url=None, description=None, patterns=None, urlconf=None, version=None):
        assert coreapi, '`coreapi` must be installed for schema support.'
        assert coreschema, '`coreschema` must be installed for schema support.'

        super(SchemaGenerator, self).__init__(title, url, description, patterns, urlconf)
        self.coerce_method_names = {
            'retrieve': 'read',
            'destroy': 'delete'
        }

    def get_links(self, request=None):
        """
        Return a dictionary containing all the links that should be
        included in the API schema.
        """
        links = LinkNode()

        paths, view_endpoints = self._get_paths_and_endpoints(request)

        # Only generate the path prefix for paths that will be included
        if not paths:
            return None
        prefix = self.determine_path_prefix(paths)

        for path, method, view in view_endpoints:
            if not self.has_view_permissions(path, method, view):
                continue
            link = view.schema.get_link(path, method, base_url=self.url)
            subpath = path[len(prefix):]
            keys = self.get_keys(subpath, method, view)
            insert_into(links, keys, link)

        return links

    def get_schema(self, request=None, public=False):
        """
        Generate a `coreapi.Document` representing the API schema.
        """
        self._initialise_endpoints()

        links = self.get_links(None if public else request)
        if not links:
            return None

        url = self.url
        if not url and request is not None:
            url = request.build_absolute_uri()

        distribute_links(links)
        return coreapi.Document(
            title=self.title, description=self.description,
            url=url, content=links
        )

    # Method for generating the link layout....
    def get_keys(self, subpath, method, view):
        """
        Return a list of keys that should be used to layout a link within
        the schema document.

        /users/                   ("users", "list"), ("users", "create")
        /users/{pk}/              ("users", "read"), ("users", "update"), ("users", "delete")
        /users/enabled/           ("users", "enabled")  # custom viewset list action
        /users/{pk}/star/         ("users", "star")     # custom viewset detail action
        /users/{pk}/groups/       ("users", "groups", "list"), ("users", "groups", "create")
        /users/{pk}/groups/{pk}/  ("users", "groups", "read"), ("users", "groups", "update"), ("users", "groups", "delete")
        """
        if hasattr(view, 'action'):
            # Viewsets have explicitly named actions.
            action = view.action
        else:
            # Views have no associated action, so we determine one from the method.
            if is_list_view(subpath, method, view):
                action = 'list'
            else:
                action = self.default_mapping[method.lower()]

        named_path_components = [
            component for component
            in subpath.strip('/').split('/')
            if '{' not in component
        ]

        if is_custom_action(action):
            # Custom action, eg "/users/{pk}/activate/", "/users/active/"
            if len(view.action_map) > 1:
                action = self.default_mapping[method.lower()]
                if action in self.coerce_method_names:
                    action = self.coerce_method_names[action]
                return named_path_components + [action]
            else:
                return named_path_components[:-1] + [action]

        if action in self.coerce_method_names:
            action = self.coerce_method_names[action]

        # Default action, eg "/users/", "/users/{pk}/"
        return named_path_components + [action]

    def determine_path_prefix(self, paths):
        """
        Given a list of all paths, return the common prefix which should be
        discounted when generating a schema structure.

        This will be the longest common string that does not include that last
        component of the URL, or the last component before a path parameter.

        For example:

        /api/v1/users/
        /api/v1/users/{pk}/

        The path prefix is '/api/v1'
        """
        prefixes = []
        for path in paths:
            components = path.strip('/').split('/')
            initial_components = []
            for component in components:
                if '{' in component:
                    break
                initial_components.append(component)
            prefix = '/'.join(initial_components[:-1])
            if not prefix:
                # We can just break early in the case that there's at least
                # one URL that doesn't have a path prefix.
                return '/'
            prefixes.append('/' + prefix + '/')
        return common_path(prefixes)


"""
inspectors.py   # Per-endpoint view introspection

See schemas.__init__.py for package overview.
"""
import re
from weakref import WeakKeyDictionary

from django.utils.encoding import smart_str, force_str

from rest_framework.settings import api_settings
from rest_framework.utils import formatting


class ViewInspector:
    """
    Descriptor class on APIView.

    Provide subclass for per-view schema generation
    """

    # Used in _get_description_section()
    header_regex = re.compile('^[a-zA-Z][0-9A-Za-z_]*:')

    def __init__(self):
        self.instance_schemas = WeakKeyDictionary()

    def __get__(self, instance, owner):
        """
        Enables `ViewInspector` as a Python _Descriptor_.

        This is how `view.schema` knows about `view`.

        `__get__` is called when the descriptor is accessed on the owner.
        (That will be when view.schema is called in our case.)

        `owner` is always the owner class. (An APIView, or subclass for us.)
        `instance` is the view instance or `None` if accessed from the class,
        rather than an instance.

        See: https://docs.python.org/3/howto/descriptor.html for info on
        descriptor usage.
        """
        if instance in self.instance_schemas:
            return self.instance_schemas[instance]

        self.view = instance
        return self

    def __set__(self, instance, other):
        self.instance_schemas[instance] = other
        if other is not None:
            other.view = instance

    @property
    def view(self):
        """View property."""
        assert self._view is not None, (
            "Schema generation REQUIRES a view instance. (Hint: you accessed "
            "`schema` from the view class rather than an instance.)"
        )
        return self._view

    @view.setter
    def view(self, value):
        self._view = value

    @view.deleter
    def view(self):
        self._view = None

    def get_description(self, path, method):
        """
        Determine a path description.

        This will be based on the method docstring if one exists,
        or else the class docstring.
        """
        view = self.view

        method_name = getattr(view, 'action', method.lower())
        method_docstring = getattr(view, method_name, None).__doc__
        if method_docstring:
            # An explicit docstring on the method or action.
            return self._get_description_section(view, method.lower(), formatting.dedent(smart_str(method_docstring)))
        else:
            return self._get_description_section(view, getattr(view, 'action', method.lower()),
                                                 view.get_view_description())

    def _get_description_section(self, view, header, description):
        lines = [line for line in description.splitlines()]
        current_section = ''
        sections = {'': ''}

        for line in lines:
            if self.header_regex.match(line):
                current_section, separator, lead = line.partition(':')
                sections[current_section] = lead.strip()
            else:
                sections[current_section] += '\n' + line

        # TODO: SCHEMA_COERCE_METHOD_NAMES appears here and in `SchemaGenerator.get_keys`
        coerce_method_names = {
            'retrieve': 'read',
            'destroy': 'delete'
        }
        if header in sections:
            return sections[header].strip()
        if header in coerce_method_names:
            if coerce_method_names[header] in sections:
                return sections[coerce_method_names[header]].strip()
        return sections[''].strip()


class DefaultSchema(ViewInspector):
    """Allows overriding AutoSchema using DEFAULT_SCHEMA_CLASS setting"""
    def __get__(self, instance, owner):
        result = super().__get__(instance, owner)
        if not isinstance(result, DefaultSchema):
            return result

        inspector_class = api_settings.DEFAULT_SCHEMA_CLASS
        assert issubclass(inspector_class, ViewInspector), (
            "DEFAULT_SCHEMA_CLASS must be set to a ViewInspector (usually an AutoSchema) subclass"
        )
        inspector = inspector_class()
        inspector.view = instance
        return inspector


def field_to_schema(field):
    title = force_str(field.label) if field.label else ''
    description = force_str(field.help_text) if field.help_text else ''

    if isinstance(field, (serializers.ListSerializer, serializers.ListField)):
        child_schema = field_to_schema(field.child)
        return coreschema.Array(
            items=child_schema,
            title=title,
            description=description
        )
    elif isinstance(field, serializers.DictField):
        return coreschema.Object(
            title=title,
            description=description
        )
    elif isinstance(field, serializers.Serializer):
        return coreschema.Object(
            properties=OrderedDict([
                (key, field_to_schema(value))
                for key, value
                in field.fields.items()
            ]),
            title=title,
            description=description
        )
    elif isinstance(field, serializers.ManyRelatedField):
        related_field_schema = field_to_schema(field.child_relation)

        return coreschema.Array(
            items=related_field_schema,
            title=title,
            description=description
        )
    elif isinstance(field, serializers.PrimaryKeyRelatedField):
        schema_cls = coreschema.String
        model = getattr(field.queryset, 'model', None)
        if model is not None:
            model_field = model._meta.pk
            if isinstance(model_field, models.AutoField):
                schema_cls = coreschema.Integer
        return schema_cls(title=title, description=description)
    elif isinstance(field, serializers.RelatedField):
        return coreschema.String(title=title, description=description)
    elif isinstance(field, serializers.MultipleChoiceField):
        return coreschema.Array(
            items=coreschema.Enum(enum=list(field.choices)),
            title=title,
            description=description
        )
    elif isinstance(field, serializers.ChoiceField):
        return coreschema.Enum(
            enum=list(field.choices),
            title=title,
            description=description
        )
    elif isinstance(field, serializers.BooleanField):
        return coreschema.Boolean(title=title, description=description)
    elif isinstance(field, (serializers.DecimalField, serializers.FloatField)):
        return coreschema.Number(title=title, description=description)
    elif isinstance(field, serializers.IntegerField):
        return coreschema.Integer(title=title, description=description)
    elif isinstance(field, serializers.DateField):
        return coreschema.String(
            title=title,
            description=description,
            format='date'
        )
    elif isinstance(field, serializers.DateTimeField):
        return coreschema.String(
            title=title,
            description=description,
            format='date-time'
        )
    elif isinstance(field, serializers.JSONField):
        return coreschema.Object(title=title, description=description)

    if field.style.get('base_template') == 'textarea.html':
        return coreschema.String(
            title=title,
            description=description,
            format='textarea'
        )

    return coreschema.String(title=title, description=description)


class AutoSchema(ViewInspector):
    """
    Default inspector for APIView

    Responsible for per-view introspection and schema generation.
    """
    def __init__(self, manual_fields=None):
        """
        Parameters:

        * `manual_fields`: list of `coreapi.Field` instances that
            will be added to auto-generated fields, overwriting on `Field.name`
        """
        super(AutoSchema, self).__init__()
        if manual_fields is None:
            manual_fields = []
        self._manual_fields = manual_fields

    def get_link(self, path, method, base_url):
        """
        Generate `coreapi.Link` for self.view, path and method.

        This is the main _public_ access point.

        Parameters:

        * path: Route path for view from URLConf.
        * method: The HTTP request method.
        * base_url: The project "mount point" as given to SchemaGenerator
        """
        fields = self.get_path_fields(path, method)
        fields += self.get_serializer_fields(path, method)
        fields += self.get_pagination_fields(path, method)
        fields += self.get_filter_fields(path, method)

        manual_fields = self.get_manual_fields(path, method)
        fields = self.update_fields(fields, manual_fields)

        if fields and any([field.location in ('form', 'body') for field in fields]):
            encoding = self.get_encoding(path, method)
        else:
            encoding = None

        description = self.get_description(path, method)

        if base_url and path.startswith('/'):
            path = path[1:]

        return coreapi.Link(
            url=parse.urljoin(base_url, path),
            action=method.lower(),
            encoding=encoding,
            fields=fields,
            description=description
        )

    def get_path_fields(self, path, method):
        """
        Return a list of `coreapi.Field` instances corresponding to any
        templated path variables.
        """
        view = self.view
        model = getattr(getattr(view, 'queryset', None), 'model', None)
        fields = []

        for variable in uritemplate.variables(path):
            title = ''
            description = ''
            schema_cls = coreschema.String
            kwargs = {}
            if model is not None:
                # Attempt to infer a field description if possible.
                try:
                    model_field = model._meta.get_field(variable)
                except Exception:
                    model_field = None

                if model_field is not None and model_field.verbose_name:
                    title = force_str(model_field.verbose_name)

                if model_field is not None and model_field.help_text:
                    description = force_str(model_field.help_text)
                elif model_field is not None and model_field.primary_key:
                    description = get_pk_description(model, model_field)

                if hasattr(view, 'lookup_value_regex') and view.lookup_field == variable:
                    kwargs['pattern'] = view.lookup_value_regex
                elif isinstance(model_field, models.AutoField):
                    schema_cls = coreschema.Integer

            field = coreapi.Field(
                name=variable,
                location='path',
                required=True,
                schema=schema_cls(title=title, description=description, **kwargs)
            )
            fields.append(field)

        return fields

    def get_serializer_fields(self, path, method):
        """
        Return a list of `coreapi.Field` instances corresponding to any
        request body input, as determined by the serializer class.
        """
        view = self.view

        if method not in ('PUT', 'PATCH', 'POST'):
            return []

        if not hasattr(view, 'get_serializer'):
            return []

        try:
            serializer = view.get_serializer()
        except exceptions.APIException:
            serializer = None
            warnings.warn('{}.get_serializer() raised an exception during '
                          'schema generation. Serializer fields will not be '
                          'generated for {} {}.'
                          .format(view.__class__.__name__, method, path))

        if isinstance(serializer, serializers.ListSerializer):
            return [
                coreapi.Field(
                    name='data',
                    location='body',
                    required=True,
                    schema=coreschema.Array()
                )
            ]

        if not isinstance(serializer, serializers.Serializer):
            return []

        fields = []
        for field in serializer.fields.values():
            if field.read_only or isinstance(field, serializers.HiddenField):
                continue

            required = field.required and method != 'PATCH'
            field = coreapi.Field(
                name=field.field_name,
                location='form',
                required=required,
                schema=field_to_schema(field)
            )
            fields.append(field)

        return fields

    def get_pagination_fields(self, path, method):
        view = self.view

        if not is_list_view(path, method, view):
            return []

        pagination = getattr(view, 'pagination_class', None)
        if not pagination:
            return []

        paginator = view.pagination_class()
        return paginator.get_schema_fields(view)

    def _allows_filters(self, path, method):
        """
        Determine whether to include filter Fields in schema.

        Default implementation looks for ModelViewSet or GenericAPIView
        actions/methods that cause filtering on the default implementation.

        Override to adjust behaviour for your view.

        Note: Introduced in v3.7: Initially "private" (i.e. with leading underscore)
            to allow changes based on user experience.
        """
        if getattr(self.view, 'filter_backends', None) is None:
            return False

        if hasattr(self.view, 'action'):
            return self.view.action in ["list", "retrieve", "update", "partial_update", "destroy"]

        return method.lower() in ["get", "put", "patch", "delete"]

    def get_filter_fields(self, path, method):
        if not self._allows_filters(path, method):
            return []

        fields = []
        for filter_backend in self.view.filter_backends:
            fields += filter_backend().get_schema_fields(self.view)
        return fields

    def get_manual_fields(self, path, method):
        return self._manual_fields

    @staticmethod
    def update_fields(fields, update_with):
        """
        Update list of coreapi.Field instances, overwriting on `Field.name`.

        Utility function to handle replacing coreapi.Field fields
        from a list by name. Used to handle `manual_fields`.

        Parameters:

        * `fields`: list of `coreapi.Field` instances to update
        * `update_with: list of `coreapi.Field` instances to add or replace.
        """
        if not update_with:
            return fields

        by_name = OrderedDict((f.name, f) for f in fields)
        for f in update_with:
            by_name[f.name] = f
        fields = list(by_name.values())
        return fields

    def get_encoding(self, path, method):
        """
        Return the 'encoding' parameter to use for a given endpoint.
        """
        view = self.view

        # Core API supports the following request encodings over HTTP...
        supported_media_types = {
            'application/json',
            'application/x-www-form-urlencoded',
            'multipart/form-data',
        }
        parser_classes = getattr(view, 'parser_classes', [])
        for parser_class in parser_classes:
            media_type = getattr(parser_class, 'media_type', None)
            if media_type in supported_media_types:
                return media_type
            # Raw binary uploads are supported with "application/octet-stream"
            if media_type == '*/*':
                return 'application/octet-stream'

        return None


