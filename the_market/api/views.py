from django.shortcuts import get_object_or_404
from rest_framework.generics import ListCreateAPIView, RetrieveUpdateDestroyAPIView, ListAPIView, CreateAPIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework.exceptions import PermissionDenied
from rest_framework.decorators import api_view
from django.contrib.auth.hashers import make_password
import logging
logger = logging.getLogger(__name__)


from django.contrib.auth.models import User
from django.db import transaction

from .models import Item, Order, Profile
from .serializers import UserSerializer, ItemSerializer, OrderSerializer, ProfileSerializer
from .permissions import IsAdmin, IsSeller, IsBuyer

from django.db.utils import IntegrityError

class RegisterView(APIView):
    permission_classes = [AllowAny]
    def post(self, request, *args, **kwargs):
        username = request.data.get('username')
        password = request.data.get('password')
        role = request.data.get('role')

        try:
            user = User.objects.create_user(username=username, password=password)
            Profile.objects.create(user=user, role=role)
            return Response({"message": "User created successfully"}, status=status.HTTP_201_CREATED)
        except IntegrityError:
            return Response({"error": "User already exists"}, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        user = User.objects.filter(username=username).first()
        if user and user.check_password(password):
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'user': {
                    'username': user.username,
                    'role': user.profile.role,
                }
            })
        return Response({'error': 'Invalid Credentials'}, status=status.HTTP_401_UNAUTHORIZED)


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['username'] = user.username
        token['role'] = user.profile.role
        return token

class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

# Profile Management

class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        profile = user.profile 
        serializer = ProfileSerializer(profile)
        return Response(serializer.data)


class ProfileListCreateView(ListCreateAPIView):
    queryset = Profile.objects.all()
    serializer_class = ProfileSerializer
    permission_classes = [IsAuthenticated, IsAdmin]


class ProfileDetailView(RetrieveUpdateDestroyAPIView):
    queryset = Profile.objects.all()
    serializer_class = ProfileSerializer
    permission_classes = [IsAuthenticated, IsAdmin]

# Item Management

class ItemListView(ListCreateAPIView):
    queryset = Item.objects.all()
    serializer_class = ItemSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)

class ItemDetailView(RetrieveUpdateDestroyAPIView):
    queryset = Item.objects.all()
    serializer_class = ItemSerializer
    permission_classes = [IsAuthenticated]

    def perform_update(self, serializer):
        if self.request.user.profile.role != 'seller':
            raise PermissionDenied('Only sellers can update items')
        serializer.save()

    def perform_destroy(self, instance):
        if self.request.user.profile.role != 'admin':
            raise PermissionDenied('Only admins can delete items')
        instance.delete()

# Order Management

class OrderListCreateView(ListCreateAPIView):
    queryset = Order.objects.all()
    serializer_class = OrderSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

class OrderDetailView(RetrieveUpdateDestroyAPIView):
    queryset = Order.objects.all()
    serializer_class = OrderSerializer
    permission_classes = [IsAuthenticated]

    def perform_update(self, serializer):
        if self.request.user.profile.role != 'buyer' and self.request.user.profile.role != 'admin':
            raise PermissionDenied('Only buyers or admins can update orders')
        serializer.save()

    def perform_destroy(self, instance):
        if self.request.user.profile.role != 'buyer' and self.request.user.profile.role != 'admin':
            raise PermissionDenied('Only buyers or admins can cancel orders')
        instance.delete()

# Checkout

class CheckoutView(APIView):
    permission_classes = [IsAuthenticated, IsBuyer]

    @transaction.atomic
    def post(self, request):
        user = request.user
        items_data = request.data.get('items', [])

        if not items_data:
            return Response({"error": "No items provided for checkout"}, status=status.HTTP_400_BAD_REQUEST)

        total_price = 0
        for item_data in items_data:
            try:
                item = Item.objects.get(id=item_data['id'])
            except Item.DoesNotExist:
                return Response({"error": f"Item with id {item_data['id']} not found"}, status=status.HTTP_404_NOT_FOUND)
            
            quantity = item_data['quantity']
            total_price += item.price * quantity

            Order.objects.create(item=item, user=user, quantity=quantity)

        return Response({"message": "Checkout successful", "total_price": total_price}, status=status.HTTP_201_CREATED)
    


