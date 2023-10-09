from django.contrib import admin
from django.urls import path,include
# from rest_framework.authtoken.views import view
# from api.auth import CustomAuthToken
from rest_framework.routers import DefaultRouter
# from .views import ItemViewSet


from .views import *

router = DefaultRouter()
router.register(r'items', ItemViewSet)

urlpatterns = [
    path('signup/', UserRegisterViewAPIView.as_view()),
    path('api/token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/login-profile/', LoginView.as_view(), name='login'),
    path('forget-password/', ForgotPasswordView.as_view(),name='forgetpassword'),
    path('reset_password/<str:reset_token>/',ResetPasswordView.as_view(), name='reset-password'),
    path('chnage-password/', ChnagePasswordAPIView.as_view(), name = 'chnage user password'),

    path('admin-login/', AdminLoginView.as_view(), name='admin-login'),

    path('admin-token/', AdminTokenObtainPairView.as_view(), name='admin-token'),
    path('admin-profile/', admin_profile, name='admin-profile'),
    path('change-admin-password/',change_admin_password, name='change-admin-password'),
    path('forgot-password/', forgot_password, name='forgot-password'),
    # path('reset-password/<str:token>/', reset_password, name='reset-password'),

    




    path('', include(router.urls))           

]   