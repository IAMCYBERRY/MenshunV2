"""
Microsoft Sentinel Integration Module
Handles sending security events to Microsoft Sentinel for monitoring and threat detection
"""

import json
import logging
import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from urllib.parse import urljoin
import requests
from azure.identity import DefaultAzureCredential, ManagedIdentityCredential
from azure.monitor.ingestion import LogsIngestionClient
from azure.core.exceptions import AzureError
from django.conf import settings
from django.utils import timezone as django_timezone
from django.core.cache import cache
from .models import SentinelIntegration, SentinelEvent

logger = logging.getLogger(__name__)


@dataclass
class SentinelEventData:
    """Standard event data structure for Sentinel"""
    TimeGenerated: str
    EventType: str
    EventSubType: str
    Severity: str
    User: Optional[str] = None
    SourceIP: Optional[str] = None
    UserAgent: Optional[str] = None
    Result: Optional[str] = None
    Details: Optional[Dict[str, Any]] = None
    RiskLevel: str = "Medium"
    Category: str = "Security"
    TenantId: Optional[str] = None
    
    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        # Remove None values to keep payload clean
        return {k: v for k, v in data.items() if v is not None}


class SentinelConnector:
    """Base class for Sentinel connectors"""
    
    def __init__(self, config: SentinelIntegration):
        self.config = config
        self.logger = logger
        
    async def send_event(self, event_data: SentinelEventData) -> bool:
        """Send single event to Sentinel"""
        raise NotImplementedError
        
    async def send_batch(self, events: List[SentinelEventData]) -> bool:
        """Send batch of events to Sentinel"""
        raise NotImplementedError


class LogAnalyticsConnector(SentinelConnector):
    """Log Analytics Workspace connector for direct ingestion"""
    
    def __init__(self, config: SentinelIntegration):
        super().__init__(config)
        self.credential = self._get_credential()
        self.client = self._create_client()
    
    def _get_credential(self):
        """Get Azure credential for authentication"""
        try:
            # Try Managed Identity first (recommended for production)
            return ManagedIdentityCredential()
        except Exception:
            # Fallback to default credential chain
            return DefaultAzureCredential()
    
    def _create_client(self):
        """Create Log Analytics ingestion client"""
        try:
            return LogsIngestionClient(
                endpoint=self.config.data_collection_endpoint,
                credential=self.credential
            )
        except Exception as e:
            self.logger.error(f"Failed to create Log Analytics client: {e}")
            return None
    
    async def send_event(self, event_data: SentinelEventData) -> bool:
        """Send single event to Log Analytics"""
        return await self.send_batch([event_data])
    
    async def send_batch(self, events: List[SentinelEventData]) -> bool:
        """Send batch of events to Log Analytics"""
        if not self.client:
            self.logger.error("Log Analytics client not initialized")
            return False
        
        try:
            # Convert events to dictionaries
            event_dicts = [event.to_dict() for event in events]
            
            # Send to Log Analytics
            self.client.upload(
                rule_id=self.config.data_collection_rule_id,
                stream_name=self.config.stream_name,
                logs=event_dicts
            )
            
            self.logger.info(f"Successfully sent {len(events)} events to Sentinel")
            return True
            
        except AzureError as e:
            self.logger.error(f"Azure error sending events to Sentinel: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error sending events to Sentinel: {e}")
            return False


class SyslogConnector(SentinelConnector):
    """Syslog connector for traditional SIEM integration"""
    
    def __init__(self, config: SentinelIntegration):
        super().__init__(config)
        self.syslog_endpoint = getattr(settings, 'SENTINEL_SYSLOG_ENDPOINT', None)
        self.facility = 16  # local0
    
    async def send_event(self, event_data: SentinelEventData) -> bool:
        """Send single event via syslog"""
        return await self.send_batch([event_data])
    
    async def send_batch(self, events: List[SentinelEventData]) -> bool:
        """Send batch of events via syslog"""
        try:
            for event in events:
                # Format as CEF (Common Event Format)
                cef_message = self._format_cef(event)
                
                # Send via syslog (implementation depends on your syslog setup)
                self._send_syslog_message(cef_message)
            
            self.logger.info(f"Successfully sent {len(events)} events via syslog")
            return True
            
        except Exception as e:
            self.logger.error(f"Error sending events via syslog: {e}")
            return False
    
    def _format_cef(self, event: SentinelEventData) -> str:
        """Format event as Common Event Format (CEF)"""
        # CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
        return (
            f"CEF:0|Menshun|PAM|1.0|{event.EventType}|{event.EventSubType}|"
            f"{self._map_severity(event.Severity)}|"
            f"src={event.SourceIP or 'unknown'} "
            f"suser={event.User or 'unknown'} "
            f"rt={event.TimeGenerated} "
            f"cat={event.Category} "
            f"outcome={event.Result or 'unknown'}"
        )
    
    def _map_severity(self, severity: str) -> int:
        """Map severity to CEF numeric values"""
        mapping = {
            'LOW': 3,
            'MEDIUM': 6,
            'HIGH': 8,
            'CRITICAL': 10
        }
        return mapping.get(severity.upper(), 6)
    
    def _send_syslog_message(self, message: str):
        """Send message via syslog (placeholder - implement based on your setup)"""
        # This would typically use a syslog library or HTTP endpoint
        self.logger.debug(f"Syslog message: {message}")


class SentinelEventMapper:
    """Maps Menshun events to Sentinel format"""
    
    @staticmethod
    def map_authentication_event(user, request, success: bool, details: Dict = None) -> SentinelEventData:
        """Map authentication event"""
        return SentinelEventData(
            TimeGenerated=datetime.now(timezone.utc).isoformat(),
            EventType="Authentication",
            EventSubType="Login",
            Severity="MEDIUM" if success else "HIGH",
            User=getattr(user, 'email', str(user)) if user else None,
            SourceIP=SentinelEventMapper._get_client_ip(request),
            UserAgent=SentinelEventMapper._get_user_agent(request),
            Result="Success" if success else "Failed",
            Details=details or {},
            RiskLevel="Low" if success else "High",
            Category="Authentication"
        )
    
    @staticmethod
    def map_vault_access_event(user, action: str, vault_entry, request, details: Dict = None) -> SentinelEventData:
        """Map vault access event"""
        severity = "HIGH" if action in ['DELETE', 'UPDATE'] else "MEDIUM"
        
        return SentinelEventData(
            TimeGenerated=datetime.now(timezone.utc).isoformat(),
            EventType="VaultAccess",
            EventSubType=action,
            Severity=severity,
            User=getattr(user, 'email', str(user)) if user else None,
            SourceIP=SentinelEventMapper._get_client_ip(request),
            UserAgent=SentinelEventMapper._get_user_agent(request),
            Result="Success",
            Details={
                "VaultEntryName": vault_entry.name if vault_entry else "Unknown",
                "CredentialType": vault_entry.credential_type.name if vault_entry and vault_entry.credential_type else "Unknown",
                **(details or {})
            },
            RiskLevel="Medium",
            Category="DataAccess"
        )
    
    @staticmethod
    def map_service_identity_event(user, action: str, identity_type: str, identity_id: str, 
                                 request, details: Dict = None) -> SentinelEventData:
        """Map service identity event"""
        severity = "HIGH" if action in ['CREATE', 'DELETE'] else "MEDIUM"
        
        return SentinelEventData(
            TimeGenerated=datetime.now(timezone.utc).isoformat(),
            EventType="ServiceIdentity",
            EventSubType=f"{identity_type}_{action}",
            Severity=severity,
            User=getattr(user, 'email', str(user)) if user else None,
            SourceIP=SentinelEventMapper._get_client_ip(request),
            UserAgent=SentinelEventMapper._get_user_agent(request),
            Result="Success",
            Details={
                "IdentityType": identity_type,
                "IdentityId": identity_id,
                "Action": action,
                **(details or {})
            },
            RiskLevel="Medium",
            Category="IdentityManagement"
        )
    
    @staticmethod
    def map_privileged_access_event(user, action: str, target_user, role: str, 
                                  request, details: Dict = None) -> SentinelEventData:
        """Map privileged access event"""
        return SentinelEventData(
            TimeGenerated=datetime.now(timezone.utc).isoformat(),
            EventType="PrivilegedAccess",
            EventSubType=action,
            Severity="HIGH",
            User=getattr(user, 'email', str(user)) if user else None,
            SourceIP=SentinelEventMapper._get_client_ip(request),
            UserAgent=SentinelEventMapper._get_user_agent(request),
            Result="Success",
            Details={
                "TargetUser": getattr(target_user, 'email', str(target_user)) if target_user else None,
                "Role": role,
                "Action": action,
                **(details or {})
            },
            RiskLevel="High",
            Category="PrivilegeManagement"
        )
    
    @staticmethod
    def _get_client_ip(request) -> Optional[str]:
        """Extract client IP from request"""
        if not request:
            return None
        
        # Check for X-Forwarded-For header (load balancer/proxy)
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        
        # Check for X-Real-IP header
        x_real_ip = request.META.get('HTTP_X_REAL_IP')
        if x_real_ip:
            return x_real_ip
        
        # Fallback to REMOTE_ADDR
        return request.META.get('REMOTE_ADDR')
    
    @staticmethod
    def _get_user_agent(request) -> Optional[str]:
        """Extract user agent from request"""
        if not request:
            return None
        return request.META.get('HTTP_USER_AGENT')


class SentinelService:
    """Main service for Sentinel integration"""
    
    def __init__(self):
        self.config = self._get_config()
        self.connector = self._create_connector()
        self.event_queue = []
        self.batch_timer = None
    
    def _get_config(self) -> Optional[SentinelIntegration]:
        """Get active Sentinel configuration"""
        try:
            return SentinelIntegration.objects.filter(enabled=True).first()
        except Exception as e:
            logger.error(f"Error getting Sentinel config: {e}")
            return None
    
    def _create_connector(self) -> Optional[SentinelConnector]:
        """Create appropriate connector based on configuration"""
        if not self.config or not self.config.is_configured():
            return None
        
        if self.config.connector_type == 'LOG_ANALYTICS':
            return LogAnalyticsConnector(self.config)
        elif self.config.connector_type == 'SYSLOG':
            return SyslogConnector(self.config)
        else:
            logger.error(f"Unsupported connector type: {self.config.connector_type}")
            return None
    
    def is_enabled(self) -> bool:
        """Check if Sentinel integration is enabled and configured"""
        return self.config and self.config.is_configured() and self.connector is not None
    
    async def send_authentication_event(self, user, request, success: bool, details: Dict = None):
        """Send authentication event to Sentinel"""
        if not self.is_enabled() or not self.config.send_auth_events:
            return
        
        event_data = SentinelEventMapper.map_authentication_event(user, request, success, details)
        await self._queue_event('AUTHENTICATION', event_data, user, request)
    
    async def send_vault_access_event(self, user, action: str, vault_entry, request, details: Dict = None):
        """Send vault access event to Sentinel"""
        if not self.is_enabled() or not self.config.send_vault_events:
            return
        
        event_data = SentinelEventMapper.map_vault_access_event(user, action, vault_entry, request, details)
        await self._queue_event('VAULT_ACCESS', event_data, user, request)
    
    async def send_service_identity_event(self, user, action: str, identity_type: str, 
                                        identity_id: str, request, details: Dict = None):
        """Send service identity event to Sentinel"""
        if not self.is_enabled() or not self.config.send_service_identity_events:
            return
        
        event_data = SentinelEventMapper.map_service_identity_event(
            user, action, identity_type, identity_id, request, details
        )
        await self._queue_event('SERVICE_IDENTITY', event_data, user, request)
    
    async def send_privileged_access_event(self, user, action: str, target_user, role: str, 
                                         request, details: Dict = None):
        """Send privileged access event to Sentinel"""
        if not self.is_enabled() or not self.config.send_privileged_access_events:
            return
        
        event_data = SentinelEventMapper.map_privileged_access_event(
            user, action, target_user, role, request, details
        )
        await self._queue_event('PRIVILEGED_ACCESS', event_data, user, request)
    
    async def _queue_event(self, event_type: str, event_data: SentinelEventData, user, request):
        """Queue event for batch processing"""
        try:
            # Create SentinelEvent record for tracking
            sentinel_event = SentinelEvent.objects.create(
                event_type=event_type,
                event_subtype=event_data.EventSubType,
                user=user,
                source_ip=SentinelEventMapper._get_client_ip(request),
                user_agent=SentinelEventMapper._get_user_agent(request),
                event_data=event_data.to_dict(),
                severity=event_data.Severity
            )
            
            # Add to queue
            self.event_queue.append((sentinel_event, event_data))
            
            # Process batch if queue is full
            if len(self.event_queue) >= self.config.batch_size:
                await self._process_batch()
            else:
                # Set timer for batch timeout
                self._set_batch_timer()
                
        except Exception as e:
            logger.error(f"Error queueing Sentinel event: {e}")
    
    async def _process_batch(self):
        """Process queued events as a batch"""
        if not self.event_queue:
            return
        
        try:
            # Extract event data for sending
            events_to_send = [event_data for _, event_data in self.event_queue]
            
            # Send batch to Sentinel
            success = await self.connector.send_batch(events_to_send)
            
            # Update event records based on result
            for sentinel_event, _ in self.event_queue:
                if success:
                    sentinel_event.mark_sent()
                else:
                    sentinel_event.mark_failed("Batch send failed")
            
            # Update integration stats
            self.config.update_stats(
                events_count=len(self.event_queue),
                success=success,
                error_message=None if success else "Batch send failed"
            )
            
            # Clear queue
            self.event_queue.clear()
            
        except Exception as e:
            logger.error(f"Error processing Sentinel event batch: {e}")
            
            # Mark all events as failed
            for sentinel_event, _ in self.event_queue:
                sentinel_event.mark_failed(str(e))
            
            # Update integration stats
            self.config.update_stats(events_count=0, success=False, error_message=str(e))
            
            # Clear queue
            self.event_queue.clear()
    
    def _set_batch_timer(self):
        """Set timer for batch timeout"""
        if self.batch_timer:
            self.batch_timer.cancel()
        
        # Use asyncio to schedule batch processing
        loop = asyncio.get_event_loop()
        self.batch_timer = loop.call_later(self.config.batch_timeout, 
                                         lambda: asyncio.create_task(self._process_batch()))
    
    async def flush(self):
        """Flush any pending events"""
        if self.event_queue:
            await self._process_batch()


# Global Sentinel service instance
_sentinel_service = None

def get_sentinel_service() -> SentinelService:
    """Get or create Sentinel service instance"""
    global _sentinel_service
    if _sentinel_service is None:
        _sentinel_service = SentinelService()
    return _sentinel_service