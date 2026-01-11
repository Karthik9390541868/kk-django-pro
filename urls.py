from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('signup/', views.signup_view, name='signup'),
    path('verify-otp/', views.verify_otp, name='verify_otp'),
    path('logout/', views.logout_view, name='logout'),
    path('admin-dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('admin-bookings/', views.manage_bookings, name='manage_bookings'),
    path('booking-status/<int:booking_id>/<str:status>/', views.update_booking_status, name='update_booking_status'),

]
