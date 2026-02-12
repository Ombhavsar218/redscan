from django.urls import path
from . import views

app_name = 'rescanai'

urlpatterns = [
    path('', views.index, name='index'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('login/', views.login_view, name='login'),
    path('register/', views.register_view, name='register'),
    path('logout/', views.logout_view, name='logout'),
    path('settings/', views.settings_view, name='settings'),
    path('settings/delete-account/', views.delete_account_view, name='delete_account'),
    path('scan/new/', views.new_scan, name='new_scan'),
    path('scan/start/', views.start_scan, name='start_scan'),
    path('scan/<int:scan_id>/', views.scan_detail, name='scan_detail'),
    path('scan/<int:scan_id>/progress/', views.scan_progress_api, name='scan_progress_api'),
    path('scan/<int:scan_id>/monitor/', views.scan_progress, name='scan_progress'),
    path('scan/<int:scan_id>/delete/', views.delete_scan, name='delete_scan'),
    path('vulnerabilities/', views.vulnerability_database, name='vulnerability_database'),
    path('reports/', views.reports, name='reports'),
    path('reports/<int:scan_id>/export/<str:format_type>/', views.export_report, name='export_report'),
]
