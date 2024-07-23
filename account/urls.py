from .views import (
    OTPRequestView,
    OTPVerificationView,

)


from django.urls import path
urlpatterns = [
    path('otp-request/', OTPRequestView.as_view(), name='otp-request'),
    path('otp-verification/', OTPVerificationView.as_view(), name='otp-verification'),
]


