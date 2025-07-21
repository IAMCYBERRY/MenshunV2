# Menshen PAM – Product Requirements Document (PRD)
**Date:** July 21, 2025

---

## 📌 Overview
**Menshen** is a modern, Django-based Privileged Access Management (PAM) platform built with security, scalability, and enterprise integration in mind. It supports vault credential storage, Microsoft Entra ID integration, and fine-grained RBAC controls.

---

## 🧱 Minimal Viable Data Model (MVDM)

### User
- Based on Django's built-in user model
- Optional extension for Entra users:
```python
class CustomUser(AbstractUser):
    source = models.CharField(max_length=50, default='local')
    aad_object_id = models.CharField(max_length=255, blank=True, null=True)
```

### CredentialType
```python
class CredentialType(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True, null=True)
```

### VaultEntry
```python
class VaultEntry(models.Model):
    name = models.CharField(max_length=255)
    username = models.CharField(max_length=255)
    password = models.CharField(max_length=512)
    credential_type = models.ForeignKey(CredentialType, on_delete=models.PROTECT)
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='vault_entries')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
```

---

## 🔗 Entra Integration Design

### Goals
- Authenticate users via Microsoft Entra (Azure AD)
- Retrieve user profile and role info
- Auto-create user in Django on login
- Map Entra groups to Django groups

### OAuth Flow
- Authorization Code Flow with MSAL
- Redirect URI: `/auth/microsoft/complete`

### Required Graph Endpoints
- `/me` – User info
- `/me/memberOf` – User groups
- `/directoryRoles` – All roles
- `/directoryRoles/{id}/members` – Membership verification

### Role Mapping
| Entra Group             | Django Group     |
|------------------------|------------------|
| Menshen_Vault_Admin    | Vault Admin      |
| Menshen_Vault_Editor   | Vault Editor     |
| Menshen_Vault_Viewer   | Vault Viewer     |

---

## 🧰 Technical Architecture

### Backend Framework
- Django 4.2.7
- Django REST Framework 3.14.0
- Python 3.x

### Database & Storage
- PostgreSQL
- Redis 5.0.1
- WhiteNoise 6.6.0

### Auth & Security
- SimpleJWT 5.3.0
- Azure AD Integration + MSAL 1.25.0
- Custom Middleware (Rate limiting, audit logging)
- HTTPS via Nginx

### Async Task Processing
- Celery 5.3.4 + Redis

### File Handling
- Pillow 10.0.1
- Django File Storage
- python-magic (optional)

### Integration & API
- Microsoft Graph API
- PowerApps (optional)
- REST API (CRUD, role mapping)

### Development & Testing
- pytest-django, factory-boy, coverage

### Deployment & Infra
- Docker + Compose
- Gunicorn + Nginx
- TLS/SSL

### UI & Frontend
- Django Admin
- DRF Browsable API
- Bootstrap + (optional jazzmin or custom themes)

### Monitoring & Logging
- Django Logging + File Handlers
- Security audit logs

### Config & Environment
- python-decouple
- Docker env support

### Filtering & Search
- django-filter, DRF filters

---

## 🧱 Architecture Patterns

### Backend
- Model-View-Serializer (DRF)
- Optional Service + Repository Layers

### API
- Token-based auth (JWT)
- RESTful resources
- RBAC via groups
- API versioning-ready

### DB Design
- Normalized schema
- Soft deletes
- `created_at`, `updated_at`
- Index optimization

### Security
- Defense in Depth
- Least Privilege
- HTTPS everywhere

---

## ✅ Phase 1 Deliverables

- [x] VaultEntry CRUD (Admin + API)
- [x] Role-based access with Django Groups
- [x] Entra login with token exchange
- [x] Automatic group mapping
- [x] User dashboard (basic)
- [ ] Session monitoring (planned)
- [ ] Rotation policies (future phase)

---

## 🧠 Next Steps
- Implement Django models
- Build Entra login view with MSAL
- Add role mapping logic
- Create VaultEntry API & Dashboard
- Extend user session & access auditing

