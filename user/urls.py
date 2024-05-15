from django.urls import path
from . import views
from rest_framework_simplejwt.views import TokenRefreshView, TokenObtainPairView

urlpatterns = [
    path('signup/', views.SignUp.as_view(), name='signup'),
    path('login/', views.CustomTokenObtainPairView.as_view(), name='login'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('update/', views.UpdateUser.as_view(), name='updateuser'),
    path('all/', views.AllUsers.as_view(), name='allusers'),
]
