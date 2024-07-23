from django.contrib import admin
from .models import Seat,HallSettings,Booking
# Register your models here.
admin.site.register(Seat)
admin.site.register(HallSettings)
admin.site.register(Booking)