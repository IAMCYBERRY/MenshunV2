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
    def _get_config():
        """Get Entra integration configuration from database"""
        try:
            from .models import IntegrationConfig
            return IntegrationConfig.objects.filter(
                integration_type='ENTRA', 
                is_enabled=True
            ).first()
        except Exception:
            return None
    
    @staticmethod
    def get_tenant_id() -> str:
        config = EntraConfig._get_config()
        if config:
            return config.get_config_value('tenant_id', '')
        return getattr(settings, 'ENTRA_TENANT_ID', '')
    
    @staticmethod
    def get_client_id() -> str:
        config = EntraConfig._get_config()
        if config:
            return config.get_config_value('client_id', '')
        return getattr(settings, 'ENTRA_CLIENT_ID', '')
    
    @staticmethod
    def get_client_secret() -> str:
        config = EntraConfig._get_config()
        if config:
            return config.get_config_value('client_secret', '')
        return getattr(settings, 'ENTRA_CLIENT_SECRET', '')
    
    @staticmethod
    def get_authority() -> str:
        tenant_id = EntraConfig.get_tenant_id()
        return f"https://login.microsoftonline.com/{tenant_id}" if tenant_id else ""
    
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
    
    def search_users(self, search_term: str) -> Dict[str, Any]:
        """Search for users by name, email, or UPN"""
        try:
            headers = self.auth.get_auth_headers()
            
            # Build search filter for name, email, or UPN
            filter_query = (
                f"startswith(displayName,'{search_term}') or "
                f"startswith(givenName,'{search_term}') or "
                f"startswith(surname,'{search_term}') or "
                f"startswith(mail,'{search_term}') or "
                f"startswith(userPrincipalName,'{search_term}')"
            )
            
            # Select specific fields for search results
            select_fields = "id,displayName,givenName,surname,mail,userPrincipalName,jobTitle,department,employeeId"
            
            url = f"{self.graph_url}/users?$filter={filter_query}&$select={select_fields}&$top=10"
            
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            
            data = response.json()
            users = data.get('value', [])
            
            return {
                'success': True,
                'users': users
            }
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to search Entra users: {e}")
            return {
                'success': False,
                'error': str(e),
                'users': []
            }
    
    def get_user_with_manager(self, user_id: str) -> Dict[str, Any]:
        """Get user details including manager information"""
        try:
            headers = self.auth.get_auth_headers()
            
            # Get user details
            user_url = f"{self.graph_url}/users/{user_id}?$select=id,displayName,givenName,surname,mail,userPrincipalName,jobTitle,department,employeeId,accountEnabled"
            response = requests.get(user_url, headers=headers)
            response.raise_for_status()
            user_data = response.json()
            
            # Try to get manager information
            try:
                manager_url = f"{self.graph_url}/users/{user_id}/manager?$select=id,displayName,mail"
                manager_response = requests.get(manager_url, headers=headers)
                if manager_response.status_code == 200:
                    user_data['manager'] = manager_response.json()
                else:
                    user_data['manager'] = None
            except:
                user_data['manager'] = None
            
            return {
                'success': True,
                'user': user_data
            }
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get user details: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def create_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new user in Entra ID"""
        try:
            headers = self.auth.get_auth_headers()
            url = f"{self.graph_url}/users"
            
            # Generate mail nickname from UPN or use provided one
            mail_nickname = user_data.get('mailNickname')
            if not mail_nickname:
                # Extract from UPN (before @ symbol)
                mail_nickname = user_data['userPrincipalName'].split('@')[0]
            
            # Generate a temporary password if not provided
            import secrets
            import string
            password = user_data.get('password')
            if not password:
                # Generate a strong password
                alphabet = string.ascii_letters + string.digits + string.punctuation
                password = ''.join(secrets.choice(alphabet) for i in range(16))
            
            # Required fields for user creation
            payload = {
                "accountEnabled": user_data.get('accountEnabled', True),
                "displayName": user_data['displayName'],
                "mailNickname": mail_nickname,
                "userPrincipalName": user_data['userPrincipalName'],
                "passwordProfile": {
                    "forceChangePasswordNextSignIn": user_data.get('forceChangePassword', True),
                    "password": password
                }
            }
            
            # Optional fields
            if 'givenName' in user_data:
                payload['givenName'] = user_data['givenName']
            if 'surname' in user_data:
                payload['surname'] = user_data['surname']
            if 'mail' in user_data:
                payload['mail'] = user_data['mail']
            if 'jobTitle' in user_data:
                payload['jobTitle'] = user_data['jobTitle']
            if 'department' in user_data:
                payload['department'] = user_data['department']
            if 'employeeId' in user_data:
                payload['employeeId'] = user_data['employeeId']
            if 'usageLocation' in user_data:
                payload['usageLocation'] = user_data['usageLocation']
            
            response = requests.post(url, headers=headers, json=payload)
            response.raise_for_status()
            
            created_user = response.json()
            logger.info(f"Successfully created Entra user: {created_user['userPrincipalName']}")
            
            return {
                'success': True,
                'user_id': created_user.get('id'),
                'user': created_user,
                'password': password  # Return the generated password
            }
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to create Entra user: {e}")
            error_msg = str(e)
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"Response content: {e.response.text}")
                try:
                    error_data = e.response.json()
                    error_msg = error_data.get('error', {}).get('message', str(e))
                except:
                    error_msg = e.response.text
            
            return {
                'success': False,
                'error': error_msg
            }
    
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
    
    def reset_user_password(self, user_id: str, new_password: str = None) -> Dict[str, Any]:
        """Reset a user's password in Entra ID"""
        try:
            import secrets
            import string
            
            # Generate a strong password if not provided
            if not new_password:
                alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
                new_password = ''.join(secrets.choice(alphabet) for i in range(16))
            
            headers = self.auth.get_auth_headers()
            url = f"{self.graph_url}/users/{user_id}"
            
            password_data = {
                "passwordProfile": {
                    "forceChangePasswordNextSignIn": True,
                    "password": new_password
                }
            }
            
            response = requests.patch(url, headers=headers, json=password_data)
            response.raise_for_status()
            
            logger.info(f"Successfully reset password for Entra user: {user_id}")
            return {
                'success': True,
                'password': new_password,
                'message': 'Password reset successfully'
            }
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to reset password for Entra user {user_id}: {e}")
            return {
                'success': False,
                'error': f'Failed to reset password: {str(e)}'
            }
    
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
    
    def get_directory_roles(self) -> Dict[str, Any]:
        """Get all available directory roles"""
        try:
            headers = self.auth.get_auth_headers()
            # Get role templates instead of active roles for assignment purposes
            url = f"{self.graph_url}/directoryRoleTemplates"
            
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            
            data = response.json()
            roles = []
            for role in data.get('value', []):
                roles.append({
                    'id': role.get('id'),
                    'display_name': role.get('displayName'),
                    'description': role.get('description'),
                    'is_built_in': True
                })
            
            return {
                'success': True,
                'roles': roles
            }
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get directory roles: {e}")
            return {
                'success': False,
                'error': str(e),
                'roles': []
            }
    
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
    
    def get_user_role_assignments(self, user_id: str) -> Dict[str, Any]:
        """Get roles assigned to a user (both permanent and PIM eligible)"""
        try:
            headers = self.auth.get_auth_headers()
            role_assignments = []
            
            # Get permanent role assignments (directory roles)
            memberOf_url = f"{self.graph_url}/users/{user_id}/memberOf"
            response = requests.get(memberOf_url, headers=headers)
            response.raise_for_status()
            
            data = response.json()
            # Filter only directory roles and format for UI
            for item in data.get('value', []):
                if item.get('@odata.type') == '#microsoft.graph.directoryRole':
                    role_assignments.append({
                        'role_id': item.get('id'),
                        'display_name': item.get('displayName'),
                        'description': item.get('description'),
                        'assignment_type': 'PERMANENT',
                        'start_datetime': None,
                        'end_datetime': None
                    })
            
            # Get PIM eligible role assignments
            try:
                pim_url = f"{self.graph_url}/roleManagement/directory/roleEligibilityScheduleInstances?$filter=principalId eq '{user_id}'"
                pim_response = requests.get(pim_url, headers=headers)
                
                if pim_response.status_code == 200:
                    pim_data = pim_response.json()
                    
                    # Get role template information for PIM roles
                    role_templates = {}
                    templates_url = f"{self.graph_url}/directoryRoleTemplates"
                    templates_response = requests.get(templates_url, headers=headers)
                    
                    if templates_response.status_code == 200:
                        for template in templates_response.json().get('value', []):
                            role_templates[template.get('id')] = template
                    
                    # Process PIM eligible assignments
                    for pim_item in pim_data.get('value', []):
                        role_definition_id = pim_item.get('roleDefinitionId')
                        if role_definition_id in role_templates:
                            template = role_templates[role_definition_id]
                            role_assignments.append({
                                'role_id': role_definition_id,
                                'display_name': template.get('displayName'),
                                'description': template.get('description'),
                                'assignment_type': 'ELIGIBLE',
                                'start_datetime': pim_item.get('startDateTime'),
                                'end_datetime': pim_item.get('endDateTime')
                            })
                else:
                    logger.warning(f"Could not retrieve PIM assignments for user {user_id}: {pim_response.status_code}")
            except requests.exceptions.RequestException as e:
                logger.warning(f"PIM API call failed for user {user_id}: {e}")
            
            return {
                'success': True,
                'roles': role_assignments
            }
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get user roles for {user_id}: {e}")
            return {
                'success': False,
                'error': str(e),
                'roles': []
            }
    
    def get_user_roles(self, user_id: str) -> List[Dict[str, Any]]:
        """Get roles assigned to a user (legacy method)"""
        result = self.get_user_role_assignments(user_id)
        return result.get('roles', [])
    
    def assign_role(self, user_id: str, role_id: str, assignment_type: str = 'PERMANENT', 
                    justification: str = '', duration_hours: int = None, assigned_by=None) -> Dict[str, Any]:
        """Assign a directory role to a user"""
        try:
            headers = self.auth.get_auth_headers()
            
            # Handle PIM eligible assignments
            if assignment_type == 'ELIGIBLE':
                return self._create_pim_eligible_assignment(user_id, role_id, justification, duration_hours, assigned_by)
            
            # First, get all active directory roles to find the one that matches the template
            active_roles_url = f"{self.graph_url}/directoryRoles"
            active_roles_response = requests.get(active_roles_url, headers=headers)
            active_roles_response.raise_for_status()
            active_roles = active_roles_response.json().get('value', [])
            
            # Find the active role that matches this template ID
            active_role_id = None
            for role in active_roles:
                if role.get('roleTemplateId') == role_id:
                    active_role_id = role.get('id')
                    break
            
            # If role is not active, we need to activate it first
            if not active_role_id:
                logger.info(f"Activating role template {role_id}")
                activate_url = f"{self.graph_url}/directoryRoles"
                activate_payload = {
                    "roleTemplateId": role_id
                }
                activate_response = requests.post(activate_url, headers=headers, json=activate_payload)
                
                if activate_response.status_code not in [200, 201]:
                    logger.error(f"Failed to activate role template {role_id}. Status: {activate_response.status_code}, Response: {activate_response.text}")
                    return {
                        'success': False,
                        'error': f'Failed to activate role template. Status: {activate_response.status_code}'
                    }
                
                activated_role = activate_response.json()
                active_role_id = activated_role.get('id')
                logger.info(f"Successfully activated role template {role_id}, active role ID: {active_role_id}")
            
            # Now assign the role using the active role ID
            url = f"{self.graph_url}/directoryRoles/{active_role_id}/members/$ref"
            payload = {
                "@odata.id": f"https://graph.microsoft.com/v1.0/users/{user_id}"
            }
            
            response = requests.post(url, headers=headers, json=payload)
            
            # Check if already assigned (conflict is acceptable)
            if response.status_code == 400:
                response_text = response.text.lower()
                if "already exists" in response_text or "already a member" in response_text:
                    logger.info(f"Role {active_role_id} already assigned to user {user_id}")
                    return {
                        'success': True,
                        'assignment': {
                            'role_id': active_role_id,
                            'template_id': role_id,
                            'user_id': user_id,
                            'assignment_type': assignment_type,
                            'status': 'already_assigned'
                        }
                    }
            
            response.raise_for_status()
            
            logger.info(f"Successfully assigned role {active_role_id} to user {user_id}")
            return {
                'success': True,
                'assignment': {
                    'role_id': active_role_id,
                    'template_id': role_id,
                    'user_id': user_id,
                    'assignment_type': assignment_type,
                    'justification': justification,
                    'assigned_by': assigned_by.username if assigned_by else None
                }
            }
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to assign role {role_id} to user {user_id}: {e}")
            error_msg = str(e)
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_data = e.response.json()
                    error_msg = error_data.get('error', {}).get('message', str(e))
                except:
                    error_msg = e.response.text
            
            return {
                'success': False,
                'error': error_msg
            }
    
    def _create_pim_eligible_assignment(self, user_id: str, role_id: str, justification: str, 
                                      duration_hours: int = None, assigned_by=None) -> Dict[str, Any]:
        """Create a PIM eligible role assignment"""
        try:
            headers = self.auth.get_auth_headers()
            url = f"{self.graph_url}/roleManagement/directory/roleEligibilityScheduleRequests"
            
            # Set default duration if not provided (1 year for eligible assignments)
            if not duration_hours:
                duration_hours = 365 * 24  # 1 year
            
            from datetime import datetime, timedelta, timezone
            start_time = datetime.now(timezone.utc)
            end_time = start_time + timedelta(hours=duration_hours)
            
            payload = {
                "action": "adminAssign",
                "justification": justification or "PIM eligible role assignment via Menshun",
                "roleDefinitionId": role_id,
                "directoryScopeId": "/",
                "principalId": user_id,
                "scheduleInfo": {
                    "startDateTime": start_time.isoformat(),
                    "expiration": {
                        "type": "afterDateTime",
                        "endDateTime": end_time.isoformat()
                    }
                }
            }
            
            response = requests.post(url, headers=headers, json=payload)
            response.raise_for_status()
            
            created_assignment = response.json()
            logger.info(f"Successfully created PIM eligible assignment for user {user_id}, role {role_id}")
            
            return {
                'success': True,
                'assignment': {
                    'id': created_assignment.get('id'),
                    'role_id': role_id,
                    'user_id': user_id,
                    'assignment_type': 'ELIGIBLE',
                    'justification': justification,
                    'start_datetime': start_time.isoformat(),
                    'end_datetime': end_time.isoformat(),
                    'assigned_by': assigned_by.username if assigned_by else None
                }
            }
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to create PIM eligible assignment for user {user_id}, role {role_id}: {e}")
            error_msg = str(e)
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_data = e.response.json()
                    error_msg = error_data.get('error', {}).get('message', str(e))
                except:
                    error_msg = e.response.text
            
            return {
                'success': False,
                'error': error_msg
            }
    
    def remove_role_assignment(self, user_id: str, role_id: str, removed_by=None) -> Dict[str, Any]:
        """Remove a directory role from a user"""
        try:
            headers = self.auth.get_auth_headers()
            
            # role_id might be a template ID or active role ID, we need to handle both
            # First try to use it as an active role ID directly
            url = f"{self.graph_url}/directoryRoles/{role_id}/members/{user_id}/$ref"
            response = requests.delete(url, headers=headers)
            
            # If that fails with 404, try to find the active role by template ID
            if response.status_code == 404:
                # Get all active directory roles to find the one that matches the template
                active_roles_url = f"{self.graph_url}/directoryRoles"
                active_roles_response = requests.get(active_roles_url, headers=headers)
                active_roles_response.raise_for_status()
                active_roles = active_roles_response.json().get('value', [])
                
                # Find the active role that matches this template ID
                active_role_id = None
                for role in active_roles:
                    if role.get('roleTemplateId') == role_id:
                        active_role_id = role.get('id')
                        break
                
                if active_role_id:
                    # Try removing with the active role ID
                    url = f"{self.graph_url}/directoryRoles/{active_role_id}/members/{user_id}/$ref"
                    response = requests.delete(url, headers=headers)
                else:
                    # Role template not found or not active
                    return {
                        'success': True,  # Role wasn't assigned anyway
                        'removal': {
                            'role_id': role_id,
                            'user_id': user_id,
                            'status': 'not_assigned'
                        }
                    }
            
            if response.status_code == 404:
                return {
                    'success': True,  # Role wasn't assigned anyway
                    'removal': {
                        'role_id': role_id,
                        'user_id': user_id,
                        'status': 'not_assigned'
                    }
                }
            
            response.raise_for_status()
            
            logger.info(f"Successfully removed role {role_id} from user {user_id}")
            return {
                'success': True,
                'removal': {
                    'role_id': role_id,
                    'user_id': user_id,
                    'removed_by': removed_by.username if removed_by else None
                }
            }
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to remove role {role_id} from user {user_id}: {e}")
            error_msg = str(e)
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_data = e.response.json()
                    error_msg = error_data.get('error', {}).get('message', str(e))
                except:
                    error_msg = e.response.text
            
            return {
                'success': False,
                'error': error_msg
            }
    
    def remove_role(self, user_id: str, role_id: str) -> bool:
        """Remove a directory role from a user (legacy method)"""
        result = self.remove_role_assignment(user_id, role_id)
        return result.get('success', False)
    
    def get_role_members(self, role_id: str) -> Dict[str, Any]:
        """Get all members assigned to a specific directory role (both permanent and PIM eligible)"""
        try:
            headers = self.auth.get_auth_headers()
            formatted_members = []
            
            # Get permanent members (active directory roles)
            active_roles_url = f"{self.graph_url}/directoryRoles"
            active_roles_response = requests.get(active_roles_url, headers=headers)
            active_roles_response.raise_for_status()
            active_roles = active_roles_response.json().get('value', [])
            
            # Find the active role that matches this template ID or use the role ID directly
            active_role_id = role_id  # Default to the provided role_id
            for role in active_roles:
                if role.get('roleTemplateId') == role_id or role.get('id') == role_id:
                    active_role_id = role.get('id')
                    break
            
            # Get permanent members of the active role
            members_url = f"{self.graph_url}/directoryRoles/{active_role_id}/members"
            members_response = requests.get(members_url, headers=headers)
            
            if members_response.status_code == 200:
                members_data = members_response.json().get('value', [])
                
                # Format permanent members for UI
                for member in members_data:
                    # Only include users (not service principals or other object types)
                    if member.get('@odata.type') == '#microsoft.graph.user':
                        formatted_members.append({
                            'user_id': member.get('id'),
                            'display_name': member.get('displayName'),
                            'user_principal_name': member.get('userPrincipalName'),
                            'mail': member.get('mail'),
                            'job_title': member.get('jobTitle'),
                            'assignment_type': 'PERMANENT',
                            'start_datetime': None,
                            'end_datetime': None
                        })
            
            # Get PIM eligible members
            try:
                pim_url = f"{self.graph_url}/roleManagement/directory/roleEligibilityScheduleInstances?$filter=roleDefinitionId eq '{role_id}'"
                pim_response = requests.get(pim_url, headers=headers)
                
                if pim_response.status_code == 200:
                    pim_data = pim_response.json()
                    
                    # Get user details for PIM eligible members
                    for pim_item in pim_data.get('value', []):
                        principal_id = pim_item.get('principalId')
                        if principal_id:
                            try:
                                # Get user details
                                user_url = f"{self.graph_url}/users/{principal_id}?$select=id,displayName,userPrincipalName,mail,jobTitle"
                                user_response = requests.get(user_url, headers=headers)
                                
                                if user_response.status_code == 200:
                                    user_data = user_response.json()
                                    formatted_members.append({
                                        'user_id': user_data.get('id'),
                                        'display_name': user_data.get('displayName'),
                                        'user_principal_name': user_data.get('userPrincipalName'),
                                        'mail': user_data.get('mail'),
                                        'job_title': user_data.get('jobTitle'),
                                        'assignment_type': 'ELIGIBLE',
                                        'start_datetime': pim_item.get('startDateTime'),
                                        'end_datetime': pim_item.get('endDateTime')
                                    })
                            except requests.exceptions.RequestException as e:
                                logger.warning(f"Could not get user details for PIM member {principal_id}: {e}")
                else:
                    logger.warning(f"Could not retrieve PIM eligible assignments for role {role_id}: {pim_response.status_code}")
            except requests.exceptions.RequestException as e:
                logger.warning(f"PIM API call failed for role {role_id}: {e}")
            
            return {
                'success': True,
                'members': formatted_members
            }
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get role members for {role_id}: {e}")
            error_msg = str(e)
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_data = e.response.json()
                    error_msg = error_data.get('error', {}).get('message', str(e))
                except:
                    error_msg = e.response.text
            
            return {
                'success': False,
                'error': error_msg,
                'members': []
            }


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
            # Check if configuration is available
            if not self.is_configured():
                return {"success": False, "message": "Configuration incomplete. Please provide Tenant ID, Client ID, and Client Secret."}
                
            auth = EntraAuthenticator()
            token = auth.get_access_token()
            
            if token:
                # Try to make a simple API call that works with application permissions
                # Use /users endpoint with $top=1 to minimize response size
                headers = auth.get_auth_headers()
                response = requests.get("https://graph.microsoft.com/v1.0/users?$top=1", headers=headers)
                
                if response.status_code == 200:
                    data = response.json()
                    user_count = len(data.get('value', []))
                    return {"success": True, "message": f"Connection successful! Found {user_count} user(s) in directory."}
                elif response.status_code == 403:
                    return {"success": False, "message": "Access denied. Please check application permissions in Azure AD."}
                else:
                    return {"success": False, "message": f"API call failed with status {response.status_code}: {response.text}"}
            else:
                return {"success": False, "message": "Unable to obtain access token. Please verify credentials."}
                
        except Exception as e:
            return {"success": False, "message": f"Connection failed: {str(e)}"}