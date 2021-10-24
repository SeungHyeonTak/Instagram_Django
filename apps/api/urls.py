import debug_toolbar
from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import path, include
from rest_framework_jwt.views import obtain_jwt_token, verify_jwt_token, refresh_jwt_token

urlpatterns = [
    path('admin/', admin.site.urls),

    # json web token url
    path('api/token', obtain_jwt_token),  # token 발행
    path('api/token/verify', verify_jwt_token),  # token 유효성 검증
    path('api/token/refresh', refresh_jwt_token),  # token 갱신

    path('account/', include('apps.api.url.account', namespace='account')),
    path('use/', include('apps.api.url.use', namespace='use')),
]

if settings.DEBUG:
    # django debug toolbar
    urlpatterns += [
        path('__debug__/', include(debug_toolbar.urls))
    ]
    # media file 서빙
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
