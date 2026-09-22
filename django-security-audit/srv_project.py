import sys, os
sys.path.insert(0, "/home/user/django-5.2")
import django
from django.conf import settings
settings.configure(
    DEBUG=True, ROOT_URLCONF=__name__, ALLOWED_HOSTS=["*"],
    SECRET_KEY="x", DATABASES={}, INSTALLED_APPS=["django.contrib.contenttypes"],
)
django.setup()
from django.urls import path, re_path
from django.views.static import serve
from django.http import HttpResponse
DOCROOT = "/home/user/django-audit-harness/staticroot"
def ok(request): return HttpResponse("ok")
urlpatterns = [
    re_path(r"^static/(?P<path>.*)$", serve, {"document_root": DOCROOT, "show_indexes": True}),
    path("", ok),
]
