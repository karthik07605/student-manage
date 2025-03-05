from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from .models import Profile, Student
from .forms import Taskform, Createuserform
import os

User = get_user_model()

# Home Page
def home(request):
    return render(request, 'home.html')

# Student Login
def studentlogin(request):
    if request.user.is_authenticated:
        return redirect('studentpage')
    else:
        if request.method == "POST":
            username = request.POST.get('username')
            password = request.POST.get('password')
            user = authenticate(request, username=username, password=password)
            if user is not None:
                profile = Profile.objects.get(user=user)
                if profile.user_type == "student":
                    login(request, user)
                    return redirect('studentpage')
                else:
                    messages.error(request, "You are not a student!")
            else:
                messages.error(request, 'Invalid username or password')
        return render(request, 'studentlogin.html')

# Faculty Login
def facultylogin(request):
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            profile = Profile.objects.get(user=user)
            if profile.user_type == "teacher":
                login(request, user)
                return redirect('facultypage')    
            else:
                messages.error(request, "You are not a faculty member!")
        else:
            messages.error(request, 'Invalid username or password')
    return render(request, 'facultylogin.html')

# Student Page (Protected)
@login_required(login_url='studentlogin')
def studentpage(request):
    tasks = Student.objects.filter(user=request.user)
    form = Taskform()
    if request.method == "POST":
        form = Taskform(request.POST, request.FILES)
        if form.is_valid():
            task = form.save(commit=False)
            task.user = request.user
            task.save()
            return redirect('studentpage')    
    context = {'tasks': tasks}
    return render(request, 'studentpage.html', context)

# Faculty Page (Protected)
@login_required(login_url='facultylogin')
def facultypage(request):
    tasks = Profile.objects.filter(user_type='student')
    selected_student = None
    uploaded_files = None
    if request.method == "POST":
        student_id = request.POST.get('student_id')
        if student_id:
            selected_student = User.objects.get(id=student_id)
            uploaded_files = Student.objects.filter(user=selected_student)
    context = {'tasks': tasks, 'selected_student': selected_student, 'uploaded_files': uploaded_files}
    return render(request, 'facultypage.html', context)

# Logout
def logoutpage(request):
    logout(request)
    return redirect('home')

# Delete File
def deletefile(request, file_id):
    file_obj = get_object_or_404(Student, id=file_id)
    file_path = os.path.join(settings.MEDIA_ROOT, str(file_obj.files))
    if os.path.exists(file_path):
        os.remove(file_path)
    file_obj.delete()
    return redirect('studentpage')

# Add Student
def addstudent(request):
    form = Createuserform()
    if request.method == "POST":
        form = Createuserform(request.POST)
        if form.is_valid():
            user = form.save()
            Profile.objects.create(user=user, user_type='student')
            return redirect('addstudent')
    return render(request, 'addstudent.html', {'form': form})

# Password Reset - Request Reset Link
def password_reset_request(request):
    if request.method == "POST":
        email = request.POST.get('email')
        user = User.objects.filter(email=email).first()
        if user:
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            
            # FIX: Ensure SITE_URL is defined
            site_url = settings.SITE_URL
            reset_url = f"{site_url}/reset_password_confirm/{uid}/{token}/"

            # FIX: Ensure the template exists
            try:
                email_body = render_to_string('password_reset_email.html', {
                    'reset_url': reset_url,
                    'user': user
                })
            except Exception as e:
                messages.error(request, f"Error loading email template: {e}")
                return redirect('password_reset_request')

            send_mail(
                "Password Reset Request",
                email_body,
                settings.EMAIL_HOST_USER,
                [email],
                fail_silently=False
            )

            messages.success(request, "A password reset link has been sent to your email.")
            return redirect('studentlogin')
        else:
            messages.error(request, "No account found with this email.")
            return redirect('reset_password')
    
    return render(request, 'password_reset.html')

# Password Reset - Confirm New Password
def password_reset_confirm(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (User.DoesNotExist, ValueError, TypeError):
        user = None

    if user and default_token_generator.check_token(user, token):
        if request.method == "POST":
            new_password1 = request.POST.get('new_password1')
            new_password2 = request.POST.get('new_password2')

            if new_password1 == new_password2:
                user.set_password(new_password1)
                user.save()
                messages.success(request, "Password reset successful! You can now log in.")
                return redirect('studentlogin')
            else:
                messages.error(request, "Passwords do not match!")

        return render(request, 'password_reset_confirm.html')

    messages.error(request, "Invalid or expired reset link.")
    return redirect('studentlogin')
