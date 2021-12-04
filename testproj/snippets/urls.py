from django.conf.urls import url

from . import views

urlpatterns = [
    url('', views.SnippetList.as_view()),
    url('<int:pk>/', views.SnippetDetail.as_view()),
    url('views/<int:snippet_pk>/', views.SnippetViewerList.as_view()),
]
