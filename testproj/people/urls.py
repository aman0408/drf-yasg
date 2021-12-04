from django.conf.urls import url

from .views import IdentityViewSet, PersonViewSet

person_list = PersonViewSet.as_view({
    'get': 'list',
    'post': 'create'
})
person_detail = PersonViewSet.as_view({
    'get': 'retrieve',
    'patch': 'partial_update',
    'delete': 'destroy'
})

identity_detail = IdentityViewSet.as_view({
    'get': 'retrieve',
    'patch': 'partial_update',
})

urlpatterns = (
    url('', person_list, name='people-list'),
    url('<int:pk>', person_detail, name='person-detail'),

    url('<int:person>/identity', identity_detail,
         name='person-identity'),
)
