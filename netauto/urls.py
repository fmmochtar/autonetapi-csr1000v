from django.urls import include, path
from autonetapi import settings
from . import views
from django.conf.urls.static import static
from django.contrib.auth import views as auth_views
from rest_framework import routers

# django rest routers
router = routers.DefaultRouter()
router.register(r'users', views.UserViewSet)
router.register(r'groups', views.GroupViewSet)
router.register(r'device', views.DeviceViewSet)

urlpatterns = [
    path('', views.home, name='home'),
    path('devices/', views.devices, name='devices'),
    path('add_ip/', views.add_ip, name='add_ip'),
    path('interfaces/', views.show_interfaces, name='interfaces'),
    path('show/acl/', views.show_acl, name='show_acl'),
    path('show/interface/', views.show_interfaces, name='show_interface'),
    path('result/', views.show_config, name='result'),
    path('log/', views.log, name='log'),
    path('static_route/', views.static_route, name='static'),
    path('ospf/', views.ospf, name='ospf'),
    path('bgp/', views.bgp, name='bgp'),
    path('syslog/', views.syslog, name='syslog'),
    path('custom/', views.custom, name='custom'),
    path('api/', include(router.urls)),
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework')),
    path('login/', auth_views.LoginView.as_view(template_name="registration/login.html", redirect_authenticated_user=True), name='login'),
]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root = settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root = settings.MEDIA_ROOT)