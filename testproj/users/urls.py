from django.conf.urls import url

from users import views

urlpatterns = [
    url('', views.UserList.as_view()),
    url('<int:pk>/', views.user_detail),
]
