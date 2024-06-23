from django.urls import path
from . import views
from rest_framework_simplejwt.views import TokenRefreshView, TokenObtainPairView

urlpatterns = [
    path('signup/', views.SignUp.as_view(), name='signup'),
    path('login/', views.Login.as_view(), name='login'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('update/', views.UpdateUser.as_view(), name='updateuser'),
    path('all/', views.AllUsers.as_view(), name='allusers'),
    path('getprofile/<str:id>', views.GetProfile.as_view(), name='getprofile')

]
