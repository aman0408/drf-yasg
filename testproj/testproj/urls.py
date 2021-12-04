import user_agents
from django.conf.urls import url, include
from django.contrib import admin
from django.shortcuts import redirect
from rest_framework import permissions
from rest_framework.decorators import api_view

from drf_yasg import openapi
from drf_yasg.views import get_schema_view

swagger_info = openapi.Info(
    title="Snippets API",
    default_version='v1',
    description="""This is a demo project for the [drf-yasg](https://github.com/axnsan12/drf-yasg) Django Rest Framework library.

The `swagger-ui` view can be found [here](/cached/swagger).
The `ReDoc` view can be found [here](/cached/redoc).
The swagger YAML document can be found [here](/cached/swagger.yaml).

You can log in using the pre-existing `admin` user with password `passwordadmin`.""",  # noqa
    terms_of_service="https://www.google.com/policies/terms/",
    contact=openapi.Contact(email="contact@snippets.local"),
    license=openapi.License(name="BSD License"),
)

SchemaView = get_schema_view(
    validators=['ssv', 'flex'],
    public=True,
    permission_classes=[permissions.AllowAny],
)


@api_view(['GET'])
def plain_view(request):
    pass


def root_redirect(request):
    user_agent_string = request.META.get('HTTP_USER_AGENT', '')
    user_agent = user_agents.parse(user_agent_string)

    if user_agent.is_mobile:
        schema_view = 'cschema-redoc'
    else:
        schema_view = 'cschema-swagger-ui'

    return redirect(schema_view, permanent=True)


# urlpatterns required for settings values
required_urlpatterns = [
    url('admin/', admin.site.urls),
    # url('o/', include('oauth2_provider.urls', namespace='oauth2_provider')),
]

urlpatterns = [
    url(r'^swagger(?P<format>.json|.yaml)$', SchemaView.without_ui(cache_timeout=0),
            name='schema-json'),
    url('swagger/', SchemaView.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    url('redoc/', SchemaView.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
    url('redoc-old/', SchemaView.with_ui('redoc-old', cache_timeout=0), name='schema-redoc-old'),

    url(r'^cached/swagger(?P<format>.json|.yaml)$', SchemaView.without_ui(cache_timeout=None),
            name='cschema-json'),
    url('cached/swagger/', SchemaView.with_ui('swagger', cache_timeout=None), name='cschema-swagger-ui'),
    url('cached/redoc/', SchemaView.with_ui('redoc', cache_timeout=None), name='cschema-redoc'),

    url('', root_redirect),

    url('snippets/', include('snippets.urls')),
    url('articles/', include('articles.urls')),
    url('users/', include('users.urls')),
    url('todo/', include('todo.urls')),
    url('people/', include('people.urls')),
    url('plain/', plain_view),
] + required_urlpatterns
