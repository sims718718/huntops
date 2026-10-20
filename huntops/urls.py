from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("accounts/", include("django.contrib.auth.urls")),
    path("", include("hunts.urls")),
]

# Serves uploaded evidence in dev only; a real deployment fronts MEDIA_ROOT with the web server.
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
