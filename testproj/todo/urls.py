from django.conf.urls import url
from rest_framework import routers

from todo import views

router = routers.DefaultRouter()
router.register(r'', views.TodoViewSet)
router.register(r'another', views.TodoAnotherViewSet)
router.register(r'yetanother', views.TodoYetAnotherViewSet)
router.register(r'tree', views.TodoTreeView)
router.register(r'recursive', views.TodoRecursiveView)
router.register(r'harvest', views.HarvestViewSet)

urlpatterns = router.urls

urlpatterns += [
    url(r'<int:todo_id>/yetanothers/<int:yetanother_id>/',
         views.NestedTodoView.as_view(), ),
]
