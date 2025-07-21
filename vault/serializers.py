from rest_framework import serializers
from django.contrib.auth.models import Group
from .models import CustomUser, CredentialType, VaultEntry, VaultAccessLog


class GroupSerializer(serializers.ModelSerializer):
    """Serializer for Django Groups"""
    class Meta:
        model = Group
        fields = ['id', 'name']


class CustomUserSerializer(serializers.ModelSerializer):
    """Serializer for CustomUser"""
    groups = GroupSerializer(many=True, read_only=True)
    full_name = serializers.SerializerMethodField()
    
    class Meta:
        model = CustomUser
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name', 'full_name',
            'source', 'aad_object_id', 'groups', 'is_active', 'date_joined'
        ]
        read_only_fields = ['id', 'username', 'source', 'aad_object_id', 'date_joined']
    
    def get_full_name(self, obj):
        return f"{obj.first_name} {obj.last_name}".strip()


class CredentialTypeSerializer(serializers.ModelSerializer):
    """Serializer for CredentialType"""
    vault_entries_count = serializers.SerializerMethodField()
    
    class Meta:
        model = CredentialType
        fields = ['id', 'name', 'description', 'vault_entries_count', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def get_vault_entries_count(self, obj):
        return obj.vault_entries.filter(is_deleted=False).count()


class VaultEntryListSerializer(serializers.ModelSerializer):
    """Serializer for VaultEntry list view (without sensitive data)"""
    credential_type = CredentialTypeSerializer(read_only=True)
    owner = CustomUserSerializer(read_only=True)
    password_length = serializers.SerializerMethodField()
    
    class Meta:
        model = VaultEntry
        fields = [
            'id', 'name', 'username', 'password_length', 'credential_type', 'owner',
            'url', 'notes', 'last_accessed', 'access_count', 'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'last_accessed', 'access_count', 'created_at', 'updated_at'
        ]
    
    def get_password_length(self, obj):
        return len(obj.password) if obj.password else 0


class VaultEntryDetailSerializer(serializers.ModelSerializer):
    """Serializer for VaultEntry detail view (includes password for authorized users)"""
    credential_type = CredentialTypeSerializer(read_only=True)
    credential_type_id = serializers.PrimaryKeyRelatedField(
        queryset=CredentialType.objects.filter(is_deleted=False),
        source='credential_type',
        write_only=True
    )
    owner = CustomUserSerializer(read_only=True)
    created_by = CustomUserSerializer(read_only=True)
    updated_by = CustomUserSerializer(read_only=True)
    
    class Meta:
        model = VaultEntry
        fields = [
            'id', 'name', 'username', 'password', 'credential_type', 'credential_type_id',
            'owner', 'url', 'notes', 'last_accessed', 'access_count',
            'created_at', 'updated_at', 'created_by', 'updated_by'
        ]
        read_only_fields = [
            'id', 'owner', 'last_accessed', 'access_count',
            'created_at', 'updated_at', 'created_by', 'updated_by'
        ]
        extra_kwargs = {
            'password': {'write_only': True}
        }
    
    def create(self, validated_data):
        # Set owner to the current user
        validated_data['owner'] = self.context['request'].user
        validated_data['created_by'] = self.context['request'].user
        return super().create(validated_data)
    
    def update(self, instance, validated_data):
        # Set updated_by to the current user
        validated_data['updated_by'] = self.context['request'].user
        return super().update(instance, validated_data)


class VaultAccessLogSerializer(serializers.ModelSerializer):
    """Serializer for VaultAccessLog"""
    vault_entry = VaultEntryListSerializer(read_only=True)
    accessed_by = CustomUserSerializer(read_only=True)
    
    class Meta:
        model = VaultAccessLog
        fields = [
            'id', 'vault_entry', 'accessed_by', 'access_type',
            'timestamp', 'ip_address', 'user_agent'
        ]
        read_only_fields = fields