import random

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import user_passes_test
from django.core.mail import send_mail
from django.conf import settings

from .models import OTP
from booking.models import Booking, TravelPackage

def is_admin(user):
    return user.is_superuser

def login_view(request):
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)

        if user is not None:
            if not user.is_active:
                messages.error(request, "Account not verified. Please verify OTP.")
                return redirect('login')

            login(request, user)

            if user.is_superuser:
                return redirect('/admin-dashboard/')
            else:
                return redirect('home')
        else:
            messages.error(request, "Invalid username or password")

    return render(request, 'accounts/login.html')

def signup_view(request):
    if request.method == "POST":
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists")
            return redirect('signup')

        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already registered")
            return redirect('signup')

        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
            is_active=False
        )

        otp_code = str(random.randint(100000, 999999))
        OTP.objects.create(user=user, otp_code=otp_code)

        send_mail(
            'MS TRAVEL OTP Verification',
            f'Your OTP is {otp_code}',
            settings.DEFAULT_FROM_EMAIL,
            [email],
        )

        request.session['otp_user_id'] = user.id
        return redirect('verify_otp')

    return render(request, 'accounts/signup.html')

def verify_otp(request):
    if request.method == "POST":
        otp_entered = request.POST.get('otp')
        user_id = request.session.get('otp_user_id')

        if not user_id:
            messages.error(request, "Session expired. Please signup again.")
            return redirect('signup')

        user = User.objects.get(id=user_id)
        otp_obj = OTP.objects.filter(user=user).last()

        if otp_obj and otp_obj.otp_code == otp_entered:
            user.is_active = True
            user.save()
            otp_obj.delete()
            messages.success(request, "Account verified successfully. Please login.")
            return redirect('login')
        else:
            messages.error(request, "Invalid OTP")

    return render(request, 'accounts/verify_otp.html')

def logout_view(request):
    logout(request)
    return redirect('home')

@user_passes_test(is_admin, login_url='login')
def admin_dashboard(request):
    context = {
        'users_count': User.objects.count(),
        'bookings_count': Booking.objects.count(),
        'packages_count': TravelPackage.objects.count(),
    }
    return render(request, 'accounts/admin_dashboard.html', context)

@user_passes_test(is_admin, login_url='login')
def manage_bookings(request):
    bookings = Booking.objects.all().order_by('-booked_at')
    return render(request, 'accounts/manage_bookings.html', {'bookings': bookings})

@user_passes_test(is_admin, login_url='login')
def update_booking_status(request, booking_id, status):
    booking = get_object_or_404(Booking, id=booking_id)

    if status in ['APPROVED', 'CANCELLED']:
        booking.status = status
        booking.save()

    return redirect('manage_bookings')
