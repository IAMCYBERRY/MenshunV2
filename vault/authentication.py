import requests
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import Group
from django.conf import settings
from django.utils.decorators import method_decorator
from django_ratelimit.decorators import ratelimit
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
import msal
import logging

from .models import CustomUser
from .audit import AuditLogger

logger = logging.getLogger(__name__)


@method_decorator(
    ratelimit(key='ip', rate='5/m', method='POST', block=True),
    name='dispatch',
)
class CustomTokenObtainPairView(TokenObtainPairView):
    """Custom JWT token view with additional user info (5 POST attempts/min per IP)."""

    def post(self, request, *args, **kwargs):
        username = request.data.get('username')
        response = super().post(request, *args, **kwargs)
        
        if response.status_code == 200:
            # Add user info to the response
            try:
                user = CustomUser.objects.get(username=username)
                response.data['user'] = {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'groups': list(user.groups.values_list('name', flat=True)),
                    'source': user.source,
                }
                
                # Log successful authentication
                AuditLogger.log_auth_success(
                    user=user,
                    request=request,
                    details={'source': user.source}
                )
                
            except CustomUser.DoesNotExist:
                pass
        else:
            # Log failed authentication attempt
            if username:
                AuditLogger.log_auth_failure(
                    username=username,
                    request=request,
                    reason="Invalid credentials"
                )
                
        return response


@api_view(['POST'])
@permission_classes([AllowAny])
def logout_view(request):
    """Logout view that blacklists the refresh token"""
    try:
        refresh_token = request.data.get('refresh_token')
        if refresh_token:
            token = RefreshToken(refresh_token)
            token.blacklist()
            
            # Log logout event if user is authenticated
            if request.user.is_authenticated:
                AuditLogger.log_logout(user=request.user, request=request)
            
            return Response({'message': 'Successfully logged out'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Refresh token required'}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class MicrosoftAuthService:
    """Service for handling Microsoft Entra authentication"""
    
    def __init__(self):
        self.tenant_id = settings.AZURE_TENANT_ID
        self.client_id = settings.AZURE_CLIENT_ID
        self.client_secret = settings.AZURE_CLIENT_SECRET
        self.redirect_uri = settings.AZURE_REDIRECT_URI
        self.authority = f"https://login.microsoftonline.com/{self.tenant_id}"
        
        self.app = msal.ConfidentialClientApplication(
            client_id=self.client_id,
            client_credential=self.client_secret,
            authority=self.authority
        )
    
    def get_auth_url(self, state=None):
        """Get the authorization URL for Microsoft login"""
        scopes = ["User.Read", "Directory.Read.All"]
        return self.app.get_authorization_request_url(
            scopes=scopes,
            redirect_uri=self.redirect_uri,
            state=state
        )
    
    def get_token_from_code(self, auth_code):
        """Exchange authorization code for access token"""
        scopes = ["User.Read", "Directory.Read.All"]
        
        result = self.app.acquire_token_by_authorization_code(
            auth_code,
            scopes=scopes,
            redirect_uri=self.redirect_uri
        )
        
        if "access_token" in result:
            return result
        else:
            logger.error(f"Failed to acquire token: {result.get('error_description', 'Unknown error')}")
            return None
    
    def get_user_info(self, access_token):
        """Get user information from Microsoft Graph"""
        headers = {'Authorization': f'Bearer {access_token}'}
        
        # Get user profile
        profile_response = requests.get(
            'https://graph.microsoft.com/v1.0/me',
            headers=headers
        )
        
        if profile_response.status_code != 200:
            logger.error(f"Failed to get user profile: {profile_response.text}")
            return None
        
        user_data = profile_response.json()
        
        # Get user groups
        groups_response = requests.get(
            'https://graph.microsoft.com/v1.0/me/memberOf',
            headers=headers
        )
        
        groups = []
        if groups_response.status_code == 200:
            groups_data = groups_response.json()
            groups = [group['displayName'] for group in groups_data.get('value', [])]
        
        return {
            'profile': user_data,
            'groups': groups
        }
    
    def create_or_update_user(self, user_info):
        """Create or update Django user from Microsoft user info"""
        profile = user_info['profile']
        groups = user_info['groups']
        
        # Extract user data
        aad_object_id = profile.get('id')
        username = profile.get('userPrincipalName', '').split('@')[0]
        email = profile.get('userPrincipalName', '')
        first_name = profile.get('givenName', '')
        last_name = profile.get('surname', '')
        
        # Create or update user
        user, created = CustomUser.objects.get_or_create(
            aad_object_id=aad_object_id,
            defaults={
                'username': username,
                'email': email,
                'first_name': first_name,
                'last_name': last_name,
                'source': 'entra',
                'is_active': True,
            }
        )
        
        if not created:
            # Update existing user
            user.email = email
            user.first_name = first_name
            user.last_name = last_name
            user.is_active = True
            user.save()
        
        # Map Entra groups to Django groups
        self.map_user_groups(user, groups)
        
        return user
    
    def map_user_groups(self, user, entra_groups):
        """Map Entra groups to Django groups"""
        user.groups.clear()
        
        for entra_group, django_group in settings.ENTRA_GROUP_MAPPINGS.items():
            if entra_group in entra_groups:
                try:
                    group = Group.objects.get(name=django_group)
                    user.groups.add(group)
                    logger.info(f"Added user {user.username} to group {django_group}")
                except Group.DoesNotExist:
                    logger.warning(f"Django group '{django_group}' does not exist")


@api_view(['GET'])
@permission_classes([AllowAny])
def microsoft_login(request):
    """Initiate Microsoft authentication"""
    auth_service = MicrosoftAuthService()
    auth_url = auth_service.get_auth_url()
    
    return Response({
        'auth_url': auth_url,
        'message': 'Redirect to this URL to authenticate with Microsoft'
    })


@ratelimit(key='ip', rate='5/m', method='POST', block=True)
@api_view(['POST'])
@permission_classes([AllowAny])
def microsoft_callback(request):
    """Handle Microsoft authentication callback (5 POST attempts/min per IP)."""
    auth_code = request.data.get('code')
    
    if not auth_code:
        return Response(
            {'error': 'Authorization code is required'}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    auth_service = MicrosoftAuthService()
    
    # Exchange code for token
    token_result = auth_service.get_token_from_code(auth_code)
    if not token_result:
        return Response(
            {'error': 'Failed to obtain access token'}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Get user info from Microsoft Graph
    user_info = auth_service.get_user_info(token_result['access_token'])
    if not user_info:
        return Response(
            {'error': 'Failed to get user information'}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Create or update Django user
    try:
        user = auth_service.create_or_update_user(user_info)
        
        # Log successful Microsoft authentication
        AuditLogger.log_auth_success(
            user=user,
            request=request,
            details={
                'source': 'entra',
                'auth_method': 'microsoft_oauth'
            }
        )
        
        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        access_token = refresh.access_token
        
        return Response({
            'access_token': str(access_token),
            'refresh_token': str(refresh),
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'groups': list(user.groups.values_list('name', flat=True)),
                'source': user.source,
            }
        })
        
    except Exception as e:
        logger.error(f"Error creating/updating user: {str(e)}")
        
        # Log failed Microsoft authentication
        AuditLogger.log_auth_failure(
            username=user_info.get('profile', {}).get('userPrincipalName', 'Unknown'),
            request=request,
            reason=f"Failed to create/update user: {str(e)}",
            details={'auth_method': 'microsoft_oauth'}
        )
        
        return Response(
            {'error': 'Failed to create user account'}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )