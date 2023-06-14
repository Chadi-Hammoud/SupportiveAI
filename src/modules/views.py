from django.shortcuts import render
from django.contrib import auth
from django.contrib.auth.tokens import default_token_generator
import random
import hashlib
import io
from django.core.mail import EmailMessage
from django.http import HttpResponse
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
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
from .serializers import PatientSerializer,LoginSerializer,TherapistSerializer
from .models import *
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth import get_user_model
from django.shortcuts import redirect
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage
from django.template.loader import render_to_string


# Create your views here.

def home(request):
    return render(request, 'home.html', {"user": None})


#INTEGRATION WITH MY CALENDLTY

def mycalendly(request,user):
    print("enter mycal")
    print(user)
    data = Therapist.objects.get(username=user)
    print(data)
    print(data.Therapist_link)
    return render(request, 'mycallendly.html', {"Therapist_link":data.Therapist_link})



def mycalendlyregister(request,user):
    user_id = int(user)
    print(user_id)
    
    data = Therapist.objects.get(username=user_id)
    print(data.name)
   
    if request.method == "POST":
        link = request.POST['Therapist_link']
        print(link)
        print()
        data.Therapist_link=link
        data.save()
        print(data.Therapist_link)
    
    return render(request, 'mycalendlyregister.html', {"user": user})



#register user in database
class RegisterView(APIView):
    
    def get(self, request, format=None):
        
        return render(request, 'register.html')

    def post(self, request, format=None):
        type = request.data.get('post')
        print(type)
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
        if type == 'patient':
            serializer = PatientSerializer(data=request.data)
            print(serializer)
            if serializer.is_valid():  
                user.save()
                user.is_active = False  # Set the user as inactive initially
                serializer.save(username=user)
                
                send_verification_email(request, user)
                print("verfication sent")
                print(get_verification_link(request,user))
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            else:
               return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            serializer = TherapistSerializer(data=request.data)
            print(serializer)
            if serializer.is_valid():
                
                print(user.password)
                user.save()
                serializer.save(username=user)

                return Response(serializer.data, status=status.HTTP_201_CREATED)
                
            else:
               return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



#LOGIN FOR PATIENT OR DOCTOR    
class LoginView(APIView):
    
    def get(self, request, format=None):
        return render(request, 'login.html')

    def forget(self, request, format=None):
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
                    print(user)
                    data = Patient.objects.get(username=user)
                    print(data)
                    print('Patient has been Logged')
                    auth.login(request, user_authenticate)
                    return redirect('dash',user='P')
                        
                except Patient.DoesNotExist:
                    try:
                        data = Therapist.objects.get(username=user)
                        print('therapist has been Logged')
                        auth.login(request, user_authenticate)
                        return redirect('mycalendlyregister',user=user.id)
                    except Therapist.DoesNotExist:
                        return redirect('/')
            else:
                print('Login Failed')
                return render(request, 'login.html')
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

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
                    print(user)
                    data = Patient.objects.get(username=user)
                    print(data)
                    print('Patient has been Logged')
                    auth.login(request, user_authenticate)
                    return redirect('dash',user='P')

                except Patient.DoesNotExist:
                    try:
                        data = Therapist.objects.get(username=user)
                        print('therapist has been Logged')
                        auth.login(request, user_authenticate)
                        return redirect('mycalendlyregister',user=user.id)
                    except Therapist.DoesNotExist:
                        return redirect('/')
            else:
                print('Login Failed')
                return render(request, 'login.html')
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


#DASHBOARD 

def dash(request, user):
   
    doctors=Therapist.objects.all()
    print(user)
    if(user=='P'):
       userid = User.objects.get(username=request.user)
       data = Patient.objects.get(username=userid)
       print(data.name)

    else:
        userid = User.objects.get(username=request.user)
        data = Therapist.objects.get(username=userid)
        print(data.name)

    if request.method=='POST':
       
        doctor=request.POST['doctor']
        user1 = User.objects.get(username=doctor)
        print(user1.id)
        dctr=Therapist.objects.get(username=user1.id)
        print(dctr.Therapist_link)
        print(dctr.id)
        return redirect('mycalendly',user=user1.id)
    return render(request, 'dash.html', {'user': user, 'data': data,'doctors':doctors})

#EMAIL VERIFICATION

#send email verification for patient

def send_verification_email(request, user):
    mail_subject = 'Verify your email'
    message = get_verification_link(request, user)
    print(message)
    send_to=[user.email]
    email=EmailMessage(mail_subject, message, 'farahhtout15@example.com', send_to)
    email.send()
    return HttpResponse('Email sent successfully!')

#generate a link for account verification based on userid and token
def get_verification_link(request, user):
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)
    return f"{request.scheme}://{request.get_host()}/verify/{uid}/{token}/"


#verify the email
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


#RESET PASSWORD     
        
#reset password email verif send
def send_reset_pass(request, user,number):
    print("send reset pass")
    mail_subject = "Reset Your Password"
    #message = get_reset_link(request,user,password)
    message = str(number)  
    send_to=[user.email]
    email=EmailMessage(mail_subject, message, 'farahhtout15@example.com', send_to)
    email.send()
    return HttpResponse('Email sent successfully!')



def forget(request):
    if request.method == "POST":
        email = request.POST['email']
        try:
            user = User.objects.get(email=email)
            number=random.randint(1000, 9999)
            hashed_number = hash_number(number)
            send_reset_pass(request, user, number)
            return redirect('codeVerif',user,hashed_number)
            
        except User.DoesNotExist:
            # Handle the case where the user with the provided email doesn't exist
            return HttpResponse('User does not exist.')
    return render(request,'forget.html')

def codeVerif(request,user,hashed_number):
    user = User.objects.get(username=user)
    if request.method=="POST":
        numb=request.POST['code']
        numbhash=hash_number(numb)
        if numbhash==hashed_number:
            return redirect('changepass',user)
        else: 
            return HttpResponse("the code is not true")
    return render(request,'codeVerif.html')


   
        
def changepass(request,user):
    print("changepass")
    user = User.objects.get(username=user)
    print(user)
    if request.method=="POST":
        password=request.POST['password']
        print(password)
        user.set_password(password)
        user.save()
        return HttpResponse("your pass is changed")

    return render(request,'changepass.html')



def hash_number(number):
    hashed_number = hashlib.sha256(str(number).encode()).hexdigest()
    return hashed_number
