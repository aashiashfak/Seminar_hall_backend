# views.py

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import Seat, Booking
from .serializers import BookingSerializer
from rest_framework.permissions import IsAuthenticated


class SeatListAPIView(APIView):
    def get(self, request, *args, **kwargs):
        date = request.query_params.get('date')
        booked_seats = Booking.objects.filter(booking_date=date).values_list('seat_id', flat=True)
        seats = Seat.objects.all()

        seats_with_status = [
            {
                "id": seat.id,
                "number": seat.number,
                "is_booked": seat.id in booked_seats
            }
            for seat in seats
        ]

        return Response(seats_with_status)


class BookingCreateAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = BookingSerializer(data=request.data)
        if serializer.is_valid():
            seat = serializer.validated_data['seat']
            booking_date = serializer.validated_data['booking_date']
            user = request.user
            if Booking.objects.filter(seat=seat, booking_date=booking_date).exists():
                return Response({"error": "This seat is already booked for the selected date."}, status=status.HTTP_400_BAD_REQUEST)
            serializer.save(user=user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

