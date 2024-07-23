# serializers.py

from rest_framework import serializers
from .models import Seat, Booking, HallSettings


class BookingSerializer(serializers.ModelSerializer):
    class Meta:
        model = Booking
        fields = ['seat', 'booking_date', 'name', 'phone_number']
        read_only_fields = ['user']
