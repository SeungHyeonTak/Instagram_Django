import debug_toolbar
from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
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
