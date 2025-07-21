"""
Microsoft Entra ID (Azure AD) Integration Module
Handles account management, role assignments, and directory operations
"""
import requests
import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from django.conf import settings
from django.core.cache import cache
from .audit import AuditLogger

logger = logging.getLogger(__name__)


class EntraConfig:
    """Configuration management for Entra ID integration"""
    
    @staticmethod
    def get_tenant_id() -> str:
        return getattr(settings, 'ENTRA_TENANT_ID', '')
    
    @staticmethod
    def get_client_id() -> str:
        return getattr(settings, 'ENTRA_CLIENT_ID', '')
    
    @staticmethod
    def get_client_secret() -> str:
        return getattr(settings, 'ENTRA_CLIENT_SECRET', '')
    
    @staticmethod
    def get_authority() -> str:
        tenant_id = EntraConfig.get_tenant_id()
        return f"https://login.microsoftonline.com/{tenant_id}"
    
    @staticmethod
    def is_configured() -> bool:
        return all([
            EntraConfig.get_tenant_id(),
            EntraConfig.get_client_id(),
            EntraConfig.get_client_secret()
        ])


class EntraAuthenticator:
    """Handles authentication with Microsoft Graph API"""
    
    def __init__(self):
        self.authority = EntraConfig.get_authority()
        self.client_id = EntraConfig.get_client_id()
        self.client_secret = EntraConfig.get_client_secret()
        self.scope = ["https://graph.microsoft.com/.default"]
        self.token_cache_key = "entra_access_token"
    
    def get_access_token(self) -> Optional[str]:
        """Get cached access token or request new one"""
        # Check cache first
        cached_token = cache.get(self.token_cache_key)
        if cached_token:
            return cached_token
        
        # Request new token
        token_url = f"{self.authority}/oauth2/v2.0/token"
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        data = {
            'grant_type': 'client_credentials',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'scope': ' '.join(self.scope)
        }
        
        try:
            response = requests.post(token_url, headers=headers, data=data)
            response.raise_for_status()
            
            token_data = response.json()
            access_token = token_data.get('access_token')
            expires_in = token_data.get('expires_in', 3600)
            
            # Cache token (subtract 5 minutes for safety)
            cache.set(self.token_cache_key, access_token, expires_in - 300)
            
            logger.info("Successfully obtained Entra access token")
            return access_token
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to obtain Entra access token: {e}")
            return None
    
    def get_auth_headers(self) -> Dict[str, str]:
        """Get authorization headers for Graph API requests"""
        token = self.get_access_token()
        if not token:
            raise Exception("Unable to obtain access token")
        
        return {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }


class EntraUserManager:
    """Manages Entra ID user operations"""
    
    def __init__(self):
        self.auth = EntraAuthenticator()
        self.graph_url = "https://graph.microsoft.com/v1.0"
    
    def search_users(self, query: str) -> List[Dict[str, Any]]:
        """Search for users in Entra ID"""
        if not query or len(query) < 2:
            return []
        
        try:
            headers = self.auth.get_auth_headers()
            
            # Search by displayName, mail, or userPrincipalName
            filter_query = f"startswith(displayName,'{query}') or startswith(mail,'{query}') or startswith(userPrincipalName,'{query}')"
            url = f"{self.graph_url}/users?$filter={filter_query}&$select=id,displayName,mail,userPrincipalName,accountEnabled,jobTitle,department"
            
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            
            data = response.json()
            return data.get('value', [])
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to search Entra users: {e}")
            return []
    
    def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user details by ID"""
        try:
            headers = self.auth.get_auth_headers()
            url = f"{self.graph_url}/users/{user_id}?$select=id,displayName,mail,userPrincipalName,accountEnabled,jobTitle,department,createdDateTime,lastSignInDateTime"
            
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get Entra user {user_id}: {e}")
            return None
    
    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Get user details by email"""
        try:
            headers = self.auth.get_auth_headers()
            url = f"{self.graph_url}/users/{email}?$select=id,displayName,mail,userPrincipalName,accountEnabled,jobTitle,department,createdDateTime,lastSignInDateTime"
            
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get Entra user {email}: {e}")
            return None
    
    def create_user(self, user_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Create a new user in Entra ID"""
        try:
            headers = self.auth.get_auth_headers()
            url = f"{self.graph_url}/users"
            
            # Required fields for user creation
            payload = {
                "accountEnabled": user_data.get('accountEnabled', True),
                "displayName": user_data['displayName'],
                "mailNickname": user_data['mailNickname'],
                "userPrincipalName": user_data['userPrincipalName'],
                "passwordProfile": {
                    "forceChangePasswordNextSignIn": user_data.get('forceChangePassword', True),
                    "password": user_data['password']
                }
            }
            
            # Optional fields
            if 'mail' in user_data:
                payload['mail'] = user_data['mail']
            if 'jobTitle' in user_data:
                payload['jobTitle'] = user_data['jobTitle']
            if 'department' in user_data:
                payload['department'] = user_data['department']
            if 'usageLocation' in user_data:
                payload['usageLocation'] = user_data['usageLocation']
            
            response = requests.post(url, headers=headers, json=payload)
            response.raise_for_status()
            
            created_user = response.json()
            logger.info(f"Successfully created Entra user: {created_user['userPrincipalName']}")
            return created_user
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to create Entra user: {e}")
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"Response content: {e.response.text}")
            return None
    
    def update_user(self, user_id: str, user_data: Dict[str, Any]) -> bool:
        """Update an existing user in Entra ID"""
        try:
            headers = self.auth.get_auth_headers()
            url = f"{self.graph_url}/users/{user_id}"
            
            response = requests.patch(url, headers=headers, json=user_data)
            response.raise_for_status()
            
            logger.info(f"Successfully updated Entra user: {user_id}")
            return True
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to update Entra user {user_id}: {e}")
            return False
    
    def disable_user(self, user_id: str) -> bool:
        """Disable a user account in Entra ID"""
        return self.update_user(user_id, {"accountEnabled": False})
    
    def enable_user(self, user_id: str) -> bool:
        """Enable a user account in Entra ID"""
        return self.update_user(user_id, {"accountEnabled": True})
    
    def delete_user(self, user_id: str) -> bool:
        """Delete a user from Entra ID (soft delete)"""
        try:
            headers = self.auth.get_auth_headers()
            url = f"{self.graph_url}/users/{user_id}"
            
            response = requests.delete(url, headers=headers)
            response.raise_for_status()
            
            logger.info(f"Successfully deleted Entra user: {user_id}")
            return True
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to delete Entra user {user_id}: {e}")
            return False


class EntraRoleManager:
    """Manages Entra ID role assignments and directory roles"""
    
    def __init__(self):
        self.auth = EntraAuthenticator()
        self.graph_url = "https://graph.microsoft.com/v1.0"
    
    def get_directory_roles(self) -> List[Dict[str, Any]]:
        """Get all available directory roles"""
        try:
            headers = self.auth.get_auth_headers()
            url = f"{self.graph_url}/directoryRoles"
            
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            
            data = response.json()
            return data.get('value', [])
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get directory roles: {e}")
            return []
    
    def get_role_templates(self) -> List[Dict[str, Any]]:
        """Get all available role templates"""
        try:
            headers = self.auth.get_auth_headers()
            url = f"{self.graph_url}/directoryRoleTemplates"
            
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            
            data = response.json()
            return data.get('value', [])
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get role templates: {e}")
            return []
    
    def get_user_roles(self, user_id: str) -> List[Dict[str, Any]]:
        """Get roles assigned to a user"""
        try:
            headers = self.auth.get_auth_headers()
            url = f"{self.graph_url}/users/{user_id}/memberOf"
            
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            
            data = response.json()
            # Filter only directory roles
            roles = [item for item in data.get('value', []) if item.get('@odata.type') == '#microsoft.graph.directoryRole']
            return roles
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get user roles for {user_id}: {e}")
            return []
    
    def assign_role(self, user_id: str, role_id: str) -> bool:
        """Assign a directory role to a user (permanent assignment)"""
        try:
            headers = self.auth.get_auth_headers()
            url = f"{self.graph_url}/directoryRoles/{role_id}/members/$ref"
            
            payload = {
                "@odata.id": f"https://graph.microsoft.com/v1.0/users/{user_id}"
            }
            
            response = requests.post(url, headers=headers, json=payload)
            response.raise_for_status()
            
            logger.info(f"Successfully assigned role {role_id} to user {user_id}")
            return True
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to assign role {role_id} to user {user_id}: {e}")
            return False
    
    def remove_role(self, user_id: str, role_id: str) -> bool:
        """Remove a directory role from a user"""
        try:
            headers = self.auth.get_auth_headers()
            url = f"{self.graph_url}/directoryRoles/{role_id}/members/{user_id}/$ref"
            
            response = requests.delete(url, headers=headers)
            response.raise_for_status()
            
            logger.info(f"Successfully removed role {role_id} from user {user_id}")
            return True
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to remove role {role_id} from user {user_id}: {e}")
            return False


class EntraPIMManager:
    """Manages Privileged Identity Management (PIM) operations"""
    
    def __init__(self):
        self.auth = EntraAuthenticator()
        self.graph_url = "https://graph.microsoft.com/v1.0"
    
    def create_eligible_assignment(self, user_id: str, role_id: str, justification: str, 
                                 start_time: Optional[datetime] = None, 
                                 end_time: Optional[datetime] = None) -> bool:
        """Create an eligible role assignment in PIM"""
        try:
            headers = self.auth.get_auth_headers()
            url = f"{self.graph_url}/roleManagement/directory/roleEligibilityScheduleRequests"
            
            if not start_time:
                start_time = datetime.utcnow()
            if not end_time:
                end_time = start_time + timedelta(days=365)  # Default 1 year
            
            payload = {
                "action": "adminAssign",
                "justification": justification,
                "roleDefinitionId": role_id,
                "directoryScopeId": "/",
                "principalId": user_id,
                "scheduleInfo": {
                    "startDateTime": start_time.isoformat() + "Z",
                    "expiration": {
                        "type": "afterDateTime",
                        "endDateTime": end_time.isoformat() + "Z"
                    }
                }
            }
            
            response = requests.post(url, headers=headers, json=payload)
            response.raise_for_status()
            
            logger.info(f"Successfully created eligible assignment for user {user_id}, role {role_id}")
            return True
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to create eligible assignment: {e}")
            return False
    
    def get_eligible_assignments(self, user_id: str) -> List[Dict[str, Any]]:
        """Get eligible role assignments for a user"""
        try:
            headers = self.auth.get_auth_headers()
            url = f"{self.graph_url}/roleManagement/directory/roleEligibilityScheduleInstances?$filter=principalId eq '{user_id}'"
            
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            
            data = response.json()
            return data.get('value', [])
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get eligible assignments for {user_id}: {e}")
            return []


class EntraIntegrationService:
    """Main service class for Entra ID integration"""
    
    def __init__(self):
        self.user_manager = EntraUserManager()
        self.role_manager = EntraRoleManager()
        self.pim_manager = EntraPIMManager()
    
    def is_configured(self) -> bool:
        """Check if Entra integration is properly configured"""
        return EntraConfig.is_configured()
    
    def test_connection(self) -> Dict[str, Any]:
        """Test connection to Entra ID"""
        try:
            auth = EntraAuthenticator()
            token = auth.get_access_token()
            
            if token:
                # Try to make a simple API call
                headers = auth.get_auth_headers()
                response = requests.get("https://graph.microsoft.com/v1.0/me", headers=headers)
                
                if response.status_code == 200:
                    return {"success": True, "message": "Connection successful"}
                else:
                    return {"success": False, "message": f"API call failed: {response.status_code}"}
            else:
                return {"success": False, "message": "Unable to obtain access token"}
                
        except Exception as e:
            return {"success": False, "message": f"Connection failed: {str(e)}"}