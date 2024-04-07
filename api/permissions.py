from rest_framework.permissions import BasePermission

class IsAdmin(BasePermission):
    """
    Permission for admin users only.
    """

    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'admin'

class IsCoach(BasePermission):
    """
    Permission for coach users only.
    """

    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'coach'
    
class IsAgent(BasePermission):
    """
    Permission for agent users only.
    """

    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'agent'
    
class IsFootballPlayer(BasePermission):
    """
    Permission for football player users only.
    """

    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'football_player'