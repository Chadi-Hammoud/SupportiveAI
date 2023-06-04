from django.shortcuts import render
from django.contrib import auth
from django.contrib.auth.models import Group
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.contrib import messages
from django.urls import reverse
from django.shortcuts import redirect, render
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from .serializers import PatientSerializer,LoginSerializer
from .models import *
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage
from django.template.loader import render_to_string



# Create your views here.
def home(request):
    return render(request, 'home.html', {"user": None})

#register user in database
class RegisterView(APIView):

    def get(self, request, format=None):
        print("!")
        return render(request, 'register.html')

    def post(self, request, format=None):
        type = request.data.get('post')
        username = request.data.get('username')
        password = request.data.get('password')
        email=request.data.get('email')

        try:
            user = User.objects.get(username=username)
            print(user)
            print(username)
            return Response({'error': 'Username already exists.'}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            user = User.objects.create_user(username=username,email=email, password=password)
            print(user)

        serializer = PatientSerializer(data=request.data)
        print(serializer)
       
        if serializer.is_valid():
            
            user.is_active = False  # Set the user as inactive initially
            user.save()
            serializer.save(username=user)
            send_verification_email(request, user)
            print("verfication sent")
            print(get_verification_link(request,user))
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

import io
from django.core.mail import EmailMessage
from django.http import HttpResponse
from django.template.loader import render_to_string



def send_verification_email(request, user):
  
    mail_subject = 'Verify your email'
    message = get_verification_link(request, user)
    print(message)
    send_to=[user.email]
    email=EmailMessage(mail_subject, message, 'farahhtout15@example.com', send_to)
    email.send()
    return HttpResponse('Email sent successfully!')


#log in       
class LoginView(APIView):
    
    def get(self, request, format=None):
        return render(request, 'login.html')

    def post(self, request, format=None):
        serializer = LoginSerializer(data=request.data)
        print(serializer)
        if serializer.is_valid():
            uname = serializer.validated_data['username']
            print(uname)
            pwd = serializer.validated_data['password']
            print(pwd)
            user_authenticate = auth.authenticate(username=uname, password=pwd)
            print(user_authenticate)
            if user_authenticate is not None:
                user = User.objects.get(username=uname)
                try:
                    data = Patient.objects.get(username=user)
                    print(data)
                    print('Patient has been Logged')
                    auth.login(request, user_authenticate)
                    return redirect('dash', user="P")
                except Patient.DoesNotExist:
                    print("patient does not exsist")
                    return redirect('/')
            else:
                print('Login Failed')
                return render(request, 'login.html')
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


#just for trying the login

def dash(request, user):
   
   
    print(user)
    userid = User.objects.get(username=request.user)
    data = Patient.objects.get(username=userid)
    print(data.name)
   

    return render(request, 'dash.html', {'user': user, 'data': data})






from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes

def get_verification_link(request, user):
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)
    return f"{request.scheme}://{request.get_host()}/verify/{uid}/{token}/"





from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth import get_user_model
from django.shortcuts import redirect

def verify_email(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = get_user_model().objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, get_user_model().DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        return HttpResponse('verification_success, you can exit here end login to site')
    else:
        return HttpResponse('verification_failure')