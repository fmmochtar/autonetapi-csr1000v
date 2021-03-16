from django.contrib.auth.models import User, Group
from rest_framework import serializers
from .models import Device, AttackLog

class UserSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = User
        fields = ['url', 'username', 'email', 'groups']

class GroupSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Group
        fields = ['url', 'name']

class DeviceSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Device
        fields = ['ip_address', 'hostname']

class AttackLogSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = AttackLog
        fields = ['source_ip', 'dst_ip', 'dst_port', 'conn_protocol']

# class AttackLogSerializer(serializers.HyperlinkedModelSerializer):
#     class Meta:
#         model = AttackLog
#         fields = ['']