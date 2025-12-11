"""
API URL routing for scanner app.
"""

from django.urls import path
from scanner.api.views import check_domain

urlpatterns = [
    path('check', check_domain, name='check_domain'),
]
