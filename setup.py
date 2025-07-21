#!/usr/bin/env python3
"""
Menshen PAM Setup Script
This script sets up the initial database and creates sample data for development.
"""

import os
import sys
import django
from django.core.management import execute_from_command_line
from django.contrib.auth.models import Group

if __name__ == '__main__':
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'menshen.settings')
    django.setup()
    
    from vault.models import CustomUser, CredentialType
    
    print("🔧 Setting up Menshen PAM...")
    
    # Run migrations
    print("📋 Running migrations...")
    execute_from_command_line(['manage.py', 'migrate'])
    
    # Set up groups and permissions
    print("👥 Setting up groups and permissions...")
    execute_from_command_line(['manage.py', 'setup_groups'])
    
    # Set up sample data
    print("📊 Setting up sample credential types...")
    execute_from_command_line(['manage.py', 'setup_sample_data'])
    
    # Create superuser if it doesn't exist
    if not CustomUser.objects.filter(is_superuser=True).exists():
        print("👤 Creating superuser...")
        superuser = CustomUser.objects.create_superuser(
            username='admin',
            email='admin@example.com',
            password='admin123',
            first_name='System',
            last_name='Administrator'
        )
        print(f"   Created superuser: {superuser.username}")
    else:
        print("👤 Superuser already exists")
    
    # Create sample users for each group
    print("👥 Creating sample users...")
    
    # Vault Admin user
    if not CustomUser.objects.filter(username='vault_admin').exists():
        admin_user = CustomUser.objects.create_user(
            username='vault_admin',
            email='admin@vault.example.com',
            password='admin123',
            first_name='Vault',
            last_name='Administrator'
        )
        admin_group = Group.objects.get(name='Vault Admin')
        admin_user.groups.add(admin_group)
        print(f"   Created Vault Admin user: {admin_user.username}")
    
    # Vault Editor user
    if not CustomUser.objects.filter(username='vault_editor').exists():
        editor_user = CustomUser.objects.create_user(
            username='vault_editor',
            email='editor@vault.example.com',
            password='editor123',
            first_name='Vault',
            last_name='Editor'
        )
        editor_group = Group.objects.get(name='Vault Editor')
        editor_user.groups.add(editor_group)
        print(f"   Created Vault Editor user: {editor_user.username}")
    
    # Vault Viewer user
    if not CustomUser.objects.filter(username='vault_viewer').exists():
        viewer_user = CustomUser.objects.create_user(
            username='vault_viewer',
            email='viewer@vault.example.com',
            password='viewer123',
            first_name='Vault',
            last_name='Viewer'
        )
        viewer_group = Group.objects.get(name='Vault Viewer')
        viewer_user.groups.add(viewer_group)
        print(f"   Created Vault Viewer user: {viewer_user.username}")
    
    # Collect static files
    print("📦 Collecting static files...")
    execute_from_command_line(['manage.py', 'collectstatic', '--noinput'])
    
    print("\n✅ Menshen PAM setup completed successfully!")
    print("\n📋 Test Users Created:")
    print("   Superuser:    admin / admin123")
    print("   Vault Admin:  vault_admin / admin123")
    print("   Vault Editor: vault_editor / editor123")
    print("   Vault Viewer: vault_viewer / viewer123")
    print("\n🌐 You can now:")
    print("   1. Start the development server: python manage.py runserver")
    print("   2. Access the admin panel: http://localhost:8000/admin/")
    print("   3. Access the dashboard: http://localhost:8000/")
    print("   4. Browse the API: http://localhost:8000/api/")
    print("\n🐳 Or use Docker:")
    print("   docker-compose up --build")