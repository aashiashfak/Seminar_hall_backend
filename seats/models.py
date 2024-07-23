from django.db import models
from django.contrib.auth.models import User
# from django.db.models.signals import post_save
# from django.dispatch import receiver

class HallSettings(models.Model):
    total_seats = models.PositiveIntegerField(default=30)


    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        self.update_seats()
    #   
    def update_seats(self):
        current_seat_count = Seat.objects.count()
        print(f"Current seat count: {current_seat_count}")
        
        if self.total_seats > current_seat_count:
            for i in range(current_seat_count + 1, self.total_seats + 1):
                Seat.objects.create(number=i)
                print(f"Created seat number: {i}")
        elif self.total_seats < current_seat_count:
            seats_to_delete = Seat.objects.all()
            for seat in seats_to_delete:
                if (int(seat.number) >  self.total_seats) :
                    print(seat.number)
                    seat.delete()



    def __str__(self):
        return f'Total Seats: {self.total_seats}'

class Seat(models.Model):
    number = models.CharField(max_length=10, unique=True)

    def __str__(self):
        return f'Seat {self.number}'

class Booking(models.Model):
    user = models.ForeignKey(User, related_name='bookings', on_delete=models.CASCADE)
    seat = models.ForeignKey(Seat, related_name='bookings', on_delete=models.CASCADE)
    booking_date = models.DateField()
    name = models.CharField(max_length=255,default="")
    phone_number = models.CharField(max_length=20 ,default="")
    booked_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'{self.user.username} - {self.seat.number} on {self.booking_date}'
