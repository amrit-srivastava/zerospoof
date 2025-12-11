"""
API URL routing for scanner app.
"""

from django.urls import path
from scanner.api.views import check_domain, download_pdf

urlpatterns = [
    path('check', check_domain, name='check_domain'),
    path('download-pdf', download_pdf, name='download_pdf'),
]

