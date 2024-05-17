from django.urls import path
from .views import CheckURLView, ScreenshotView, VisualizeSubdomainsView, IPReputationView, WhoisView

urlpatterns = [
    path('check_url/', CheckURLView.as_view(), name='check_url'),
    path('screenshot/', ScreenshotView.as_view(), name='screenshot'),
    path('visualize_subdomains/', VisualizeSubdomainsView.as_view(), name='visualize_subdomains'),
    path('ip_reputation/', IPReputationView.as_view(), name='ip_reputation'),
    path('whois/', WhoisView.as_view(), name='whois'),
]

