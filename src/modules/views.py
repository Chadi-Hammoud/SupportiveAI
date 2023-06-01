from django.shortcuts import render
from django.contrib import auth
from django.contrib.auth.models import Group
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.urls import reverse
from django.shortcuts import redirect, render
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from .serializers import PatientSerializer,LoginSerializer
from .models import *

# Create your views here.
def home(request):
    return render(request, 'home.html', {"user": None})


class RegisterView(APIView):

    def get(self, request, format=None):
        print("!")
        return render(request, 'register.html')

    def post(self, request, format=None):
        type = request.data.get('post')
        username = request.data.get('username')
        password = request.data.get('password')

        try:
            user = User.objects.get(username=username)
            print(user)
            print(username)
            return Response({'error': 'Username already exists.'}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            user = User.objects.create_user(username=username, password=password)
            print(user)

        serializer = PatientSerializer(data=request.data)
        print(serializer)
       
        if serializer.is_valid():
            user.save()
            print(username)
            serializer.save(username=user)
            
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

      
class LoginView(APIView):
    
    def get(self, request, format=None):
        print("its get")
        return render(request, 'login.html')

    def post(self, request, format=None):
        print("ll2")
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



def dash(request, user):
   
    print("!2")
    print(user)
    userid = User.objects.get(username=request.user)
    data = Patient.objects.get(username=userid)
    print(data.name)
   

    return render(request, 'dash.html', {'user': user, 'data': data})