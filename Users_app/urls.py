from django.urls import path
from . import views

urlpatterns = [
    
    path('register/', views.UsersRegistrationView.as_view() , name='UserRegister'),
    path('login/', views.UsersLoginView.as_view() , name='UserLogin'),
    path('logout/', views.UsersLogOutView.as_view() , name='UserLogout'),
    path('userRegisterByPM/', views.UserCreationByPMView.as_view() , name='UserRegisterByPM'),
    path('verify-email/<str:token>/', views.UserEmailVerificationView.as_view() , name='UserEmailVerification'),
    path('usersForgotPassword/', views.UsersForgotPasswordView.as_view(), name='Users_Forgot_Password'),
    path('usersForgotPasswordOTPVerify/', views.UserForgotPasswordOTPVerifyView.as_view(), name='Users_Forgot_Password_OTP_Verify'),
    path('usersForgotPasswordChange/', views.UserForgotPasswordChangeView.as_view(), name='Users_Forgot_Password_Change'),
    path('UsersEmailVerifySendOTP/', views.UsersEmailVerifySendOTP.as_view(), name='Email_verify_send_OTP'),
    path('UsersEmailVerifyOTPVerify/', views.UsersEmailVerifyOTPVerifyView.as_view(), name='Email_verify_send_OTP'),
    path('usersDetailsUpdate/', views.UsersDetailsUpdateView.as_view(), name='Users_details_update'),
    path('UserAllDetails/', views.UserDetailView.as_view(), name='User_All_Details'),
    path('usersDelete/', views.UsersDeleteview.as_view(), name='Users_Delete'),
]

