from rest_framework import serializers
from rest_framework.settings import api_settings
from .models import *

class MessageSerializer(serializers.ModelSerializer):

    class Meta:
        model = Message
        fields = ('sender','content','timestamp')
