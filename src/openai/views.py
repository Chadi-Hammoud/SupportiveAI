from django.shortcuts import render
from django.core.serializers import serialize
from django.core.serializers.json import DjangoJSONEncoder
from django.http import JsonResponse
from rest_framework.views import APIView
from .serializers import *


from .models import Message
import json

import openai
import requests

URL = "https://api.openai.com/v1/chat/completions"

class chat_view(APIView):
    def get(self, request, format=None):
            return render(request, 'chat/chat.html')

    # def post(self,request):
    #     if request.method == 'POST':
    #         sender = request.user
    #         content = request.POST['content']
    #         message = Message(sender=sender, content=content)
    #         message.save()
    #     messages = Message.objects.all()
    #     chat_res = generate_chat_response(message)
        
    #     # serialized_messages = serialize('json', messages)
    #     serialized_messages = json.dumps(list(messages.values()), cls=DjangoJSONEncoder)


    #     return JsonResponse(serialized_messages, safe=False)

        
        
        # return render(request, 'chat/chat.html', {'messages': messages})



def post(self,request):
    serializer = MessageSerializer(data=request.data)
    print(serializer)
    if request.method == 'POST':
        sender = request.user
        content = request.POST['content']
        message = Message(sender=sender, content=content)
        message.save()
    messages = Message.objects.all()
    chat_res = generate_chat_response(message)
    
    # serialized_messages = serialize('json', messages)
    serialized_messages = json.dumps(list(messages.values()), cls=DjangoJSONEncoder)


    return JsonResponse(serialized_messages, safe=False)

        






def generate_chat_response(message):
    URL = "https://api.openai.com/v1/chat/completions"

    payload = {
        "model": "gpt-3.5-turbo",
        "messages": [{"role": "user", "content": message}],
        "temperature": 1.0,
        "top_p": 1.0,
        "n": 1,
        "stream": False,
        "presence_penalty": 0,
        "frequency_penalty": 0,
    }

    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer YOUR_OPENAI_API_KEY",  # Replace with your actual API key
    }

    response = requests.post(URL, headers=headers, json=payload, stream=False)
    
    if response.status_code == 200:
        data = response.json()
        chat_response = data['choices'][0]['message']['content']
        return chat_response
    else:
        return None