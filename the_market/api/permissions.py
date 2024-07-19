from rest_framework.permissions import BasePermission


class IsAdmin(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.profile.role == 'admin'


class IsSeller(BasePermission):
    def has_permission(self, request, view):
        return request.user.profile.role == 'seller'

class IsBuyer(BasePermission):
    def has_permission(self, request, view):
        return request.user.profile.role == 'buyer'
