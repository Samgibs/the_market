from django.urls import path
from .views import (
    RegisterView, LoginView, CustomTokenObtainPairView,
    UserProfileView, ProfileListCreateView, ProfileDetailView, 
    ItemListView, ItemDetailView,
    OrderListCreateView, OrderDetailView,
    CheckoutView
)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    
    path('api/profile/', UserProfileView.as_view(), name='user-profile'),
    path('api/profiles/', ProfileListCreateView.as_view(), name='profile-list-create'),
    path('api/profiles/<int:pk>/', ProfileDetailView.as_view(), name='profile-detail'),
    
    
    path('items/', ItemListView.as_view(), name='item-list-create'),
    path('items/<int:pk>/', ItemDetailView.as_view(), name='item-detail'),
    
    path('orders/', OrderListCreateView.as_view(), name='order-list-create'),
    path('orders/<int:pk>/', OrderDetailView.as_view(), name='order-detail'),
    
    path('checkout/', CheckoutView.as_view(), name='checkout'),
]
