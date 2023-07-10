from django.contrib import admin

# Register your models here.
from .models import Patient,Therapist
from django.contrib import admin
from .models import Patient
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User

class PatientAdmin(admin.ModelAdmin):
   
    list_display = ('id', 'name', 'email',)
    list_filter = ('name', 'email')
    search_fields = ('name', 'email')

class TherapistAdmin(admin.ModelAdmin):
   
    list_display = ('id', 'name', 'email',)
    list_filter = ('name', 'email')
    search_fields = ('name', 'email')

class CustomUserAdmin(UserAdmin):
    list_display = ('id', 'username', 'email','is_active')
    list_filter = ('is_active', 'is_staff', 'is_superuser')
    search_fields = ('username', 'email')

admin.site.unregister(User)
admin.site.register(User, CustomUserAdmin)
admin.site.register(Patient, PatientAdmin)

#admin.site.register(Patient)
admin.site.register(Therapist,TherapistAdmin)