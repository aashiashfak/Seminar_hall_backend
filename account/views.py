from .serializers import UserSerializer, OTPSerializer
from .utils import send_otp_email, generate_otp
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from .models import OTP
from django.utils import timezone
from datetime import datetime, timedelta 

class OTPRequestView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            username = email.split('@')[0]

            try:
                otp = generate_otp()
                print('Generated OTP:', otp)

                # Create or update OTP entry
                OTP.objects.update_or_create(
                    email=email,
                    defaults={'otp': otp, 'expires_at': timezone.now() + timedelta(minutes=10)}
                )

                send_otp_email(email, username, otp)  # Send OTP via email
                response_data = {"message": "OTP sent successfully"}
                return Response(response_data, status=status.HTTP_200_OK)
            except Exception as e:
                error_msg = str(e)
                return Response({'error': error_msg}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from .models import OTP
from .serializers import OTPSerializer
from django.contrib.auth.models import User

class OTPVerificationView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = OTPSerializer(data=request.data)
        if serializer.is_valid():
            entered_otp = serializer.validated_data.get('otp')
            email = serializer.validated_data.get('email')

            if entered_otp is None or email is None:
                return Response({'errors': ['OTP and email are required']}, status=status.HTTP_400_BAD_REQUEST)

            try:
                otp_record = OTP.objects.get(email=email, otp=entered_otp)
                if not otp_record.is_valid():
                    otp_record.delete()  # Clean up expired OTP
                    return Response({'errors': ['OTP has expired or is invalid']}, status=status.HTTP_400_BAD_REQUEST)

                user, created = User.objects.get_or_create(email=email, defaults={'username': email.split('@')[0]})
                refresh = RefreshToken.for_user(user)

                response_data = {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'access_token': str(refresh.access_token),
                    'refresh_token': str(refresh),
                }

                otp_record.delete()  # Clean up used OTP
                return Response(response_data, status=status.HTTP_200_OK)
            except OTP.DoesNotExist:
                return Response({'errors': ['Invalid OTP entered']}, status=status.HTTP_400_BAD_REQUEST)
        else:
            # Flattening the serializer errors into a list of error messages
            error_messages = [f"{field}: {error}" for field, errors in serializer.errors.items() for error in errors]
            return Response({'errors': error_messages}, status=status.HTTP_400_BAD_REQUEST)
