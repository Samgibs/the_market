from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Item, Order
from .models import Profile

class UserSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)
    password = serializers.CharField(write_only=True)

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            password=validated_data['password']
        )
        return user

    def validate_username(self, value):
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("Username already exists")
        return value

class ProfileSerializer(serializers.Serializer):
    role = serializers.ChoiceField(choices=Profile.ROLE_CHOICES)

    def create(self, validated_data):
        return Profile.objects.create(**validated_data)

    def update(self, instance, validated_data):
        instance.role = validated_data.get('role', instance.role)
        instance.save()
        return instance 


class ItemSerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only=True)
    name = serializers.CharField(max_length=255)
    description = serializers.CharField()
    price = serializers.DecimalField(max_digits=10, decimal_places=2)
    owner = serializers.ReadOnlyField(source='owner.username')

    def create(self, validated_data):
        return Item.objects.create(**validated_data)
    
    def delete(self, instance):
        instance.delete()


class OrderSerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only=True)
    item = serializers.PrimaryKeyRelatedField(queryset=Item.objects.all())
    user = serializers.ReadOnlyField(source='user.username')
    quantity = serializers.IntegerField()
    ordered_at = serializers.DateTimeField(read_only=True)
    cancelled = serializers.BooleanField(default=False)

    def create(self, validated_data):
        return Order.objects.create(**validated_data)
