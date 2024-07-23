from django.urls import path
from .views import SeatListAPIView,BookingCreateAPIView

urlpatterns = [
    path('list-seats/', SeatListAPIView.as_view(), name='seat-list'),
    path('bookings/', BookingCreateAPIView.as_view(), name='booking-create'),
]