from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework import generics, viewsets
import requests
import httpx

# Django REST Framework ViewSet
class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    
    def create(self, request):
        # External API call for validation
        response = requests.post('https://api.validation-service.com/users', json=request.data)
        return super().create(request)
    
    def list(self, request):
        # External API call using httpx
        async_response = httpx.get('https://external-service.com/users')
        return super().list(request)

# Router registration
router = DefaultRouter()
router.register(r'users', UserViewSet)
router.register(r'posts', PostViewSet)
router.register(r'comments', CommentViewSet)

# Generic views
class PostListView(generics.ListCreateAPIView):
    queryset = Post.objects.all()
    
    def get(self, request):
        # External API call
        external_posts = requests.get('https://jsonplaceholder.typicode.com/posts')
        return Response(external_posts.json())

urlpatterns = [
    path('api/v1/', include(router.urls)),
]