# Menshun PAM - Privileged Access Management

Menshun is a modern Django-based Privileged Access Management (PAM) platform with Microsoft Entra ID integration, built for enterprise security and scalability with a cutting-edge cyberpunk aesthetic.

## 🚀 Features

### Phase 1 (MVP) - ✅ Completed
- **VaultEntry CRUD** - Complete credential management with admin panel and REST API
- **Role-based Access Control** - Django Groups integration with three permission levels
- **Microsoft Entra Integration** - OAuth2 authentication with automatic group mapping
- **REST API** - Full CRUD operations with DRF and JWT authentication
- **Admin Panel** - Comprehensive Django admin interface with security controls
- **Basic Dashboard** - User-friendly web interface for credential management
- **Audit Logging** - Access tracking and security monitoring
- **Docker Support** - Complete containerization for development and deployment

### Security Features
- JWT-based authentication with token refresh
- Role-based permissions (Admin, Editor, Viewer)
- Soft delete for data retention
- Access logging and audit trails
- Password masking in admin interface
- IP address and user agent tracking

### Microsoft Entra Integration
- OAuth2 authentication flow with MSAL
- Automatic user creation and group mapping
- Support for directory roles and group membership
- Configurable group mappings via environment variables

## 🏗️ Architecture

### Backend Stack
- **Django 5.2.4** - Web framework
- **Django REST Framework 3.16.0** - API framework
- **PostgreSQL** - Primary database
- **Redis** - Caching and Celery backend
- **Celery** - Async task processing
- **SimpleJWT** - JWT authentication
- **MSAL** - Microsoft authentication

### Security & Deployment
- **WhiteNoise** - Static file serving
- **Gunicorn** - WSGI server
- **Docker & Docker Compose** - Containerization
- **Bootstrap 5** - Frontend UI framework

## 📋 Models

### CustomUser
Extended Django user model with Entra integration:
- `source` - Authentication source (local/entra)
- `aad_object_id` - Azure AD object identifier
- Soft delete capabilities
- Audit timestamps

### CredentialType
Categorization for different credential types:
- Database, Server, API Key, Cloud Service, etc.
- Soft delete and audit tracking

### VaultEntry
Core credential storage with security features:
- Encrypted password storage (configurable)
- Owner and permission tracking
- Access counting and timestamps
- Soft delete with audit trail
- URL and notes support

### VaultAccessLog
Comprehensive audit logging:
- Access type tracking (VIEW, CREATE, UPDATE, DELETE)
- IP address and user agent capture
- Timestamp and user tracking

## 🔐 Permission System

### Vault Admin
- Full CRUD access to all vault entries
- Credential type management
- User and group management
- Access log viewing

### Vault Editor
- Create and edit vault entries
- View all vault entries
- Cannot delete others' entries
- Read-only access to credential types

### Vault Viewer
- View own vault entries only
- Read-only access
- Cannot create, edit, or delete

## 🛠️ Quick Start

### Prerequisites
- Python 3.11+
- Docker & Docker Compose (recommended)
- PostgreSQL 15+ (if running locally)
- Redis 7+ (if running locally)

### Local Development

1. **Clone and Setup**
   ```bash
   git clone <repository>
   cd MenshunV2
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

2. **Configure Environment**
   ```bash
   cp .env.example .env
   # Edit .env with your database and Azure credentials
   ```

3. **Initialize Database**
   ```bash
   python setup.py
   ```

4. **Start Development Server**
   ```bash
   python manage.py runserver
   ```

### Docker Development (Recommended)

#### Option 1: Smart Start (Automatic Port Detection)
```bash
# Automatically detects port conflicts and configures accordingly
python3 start.py
```

#### Option 2: Manual Port Check
```bash
# Check and configure ports manually
python3 scripts/check_ports.py
docker-compose up --build
```

#### Option 3: Traditional Start
```bash
# Use pre-configured ports (may fail if ports are in use)
docker-compose up --build
```

**Features:**
- 🔍 **Automatic port conflict detection**
- 🔄 **Smart port allocation** (finds next available port)
- 📝 **Auto-updates configuration files**
- 🏥 **Service health checks**
- ⚡ **One-command startup**

## 🔧 Configuration

### Environment Variables

```bash
# Django Settings
SECRET_KEY=your-secret-key
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1

# Database
DATABASE_NAME=menshen_db
DATABASE_USER=postgres
DATABASE_PASSWORD=postgres
DATABASE_HOST=localhost
DATABASE_PORT=5432

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0

# Microsoft Entra ID
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret
AZURE_REDIRECT_URI=http://localhost:8000/auth/microsoft/complete

# Group Mappings
MENSHEN_VAULT_ADMIN_GROUP=Menshen_Vault_Admin
MENSHEN_VAULT_EDITOR_GROUP=Menshen_Vault_Editor
MENSHEN_VAULT_VIEWER_GROUP=Menshen_Vault_Viewer
```

### Microsoft Entra Setup

1. Register application in Azure Portal
2. Configure redirect URI: `http://localhost:8000/auth/microsoft/complete`
3. Add required permissions:
   - `User.Read`
   - `Directory.Read.All`
4. Create groups in Azure AD:
   - `Menshen_Vault_Admin`
   - `Menshen_Vault_Editor`
   - `Menshen_Vault_Viewer`

## 🧪 Testing

### Run Tests
```bash
# All tests
pytest

# Specific test files
pytest vault/test_models.py
pytest vault/test_api.py

# With coverage
pytest --cov=vault
```

### Test Users
The setup script creates test users:
- **Superuser**: `admin` / `admin123`
- **Vault Admin**: `vault_admin` / `admin123`
- **Vault Editor**: `vault_editor` / `editor123`
- **Vault Viewer**: `vault_viewer` / `viewer123`

## 📡 API Endpoints

### Authentication
- `POST /auth/login/` - JWT token login
- `POST /auth/refresh/` - Refresh JWT token
- `POST /auth/logout/` - Logout and blacklist token
- `GET /auth/microsoft/login/` - Initiate Microsoft login
- `POST /auth/microsoft/callback/` - Handle Microsoft callback

### Vault Management
- `GET /api/vault-entries/` - List vault entries
- `POST /api/vault-entries/` - Create vault entry
- `GET /api/vault-entries/{id}/` - Get vault entry details
- `PUT /api/vault-entries/{id}/` - Update vault entry
- `DELETE /api/vault-entries/{id}/` - Delete vault entry
- `GET /api/vault-entries/{id}/password/` - Get password
- `GET /api/vault-entries/{id}/access-logs/` - Get access logs

### Credential Types
- `GET /api/credential-types/` - List credential types
- `POST /api/credential-types/` - Create credential type (admin only)
- `GET /api/credential-types/{id}/` - Get credential type
- `PUT /api/credential-types/{id}/` - Update credential type (admin only)
- `DELETE /api/credential-types/{id}/` - Delete credential type (admin only)

## 🌐 Web Interface

### Dashboard Features
- Credential overview with statistics
- Search and filter capabilities
- Role-based UI controls
- Recent activity tracking
- Responsive Bootstrap design

### Admin Panel
- Complete CRUD operations
- Advanced filtering and search
- Bulk operations
- Audit trail viewing
- Permission management

## 🔄 Management Commands

```bash
# Setup groups and permissions
python manage.py setup_groups

# Create sample credential types
python manage.py setup_sample_data

# Run migrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser

# Collect static files
python manage.py collectstatic
```

## 📈 Future Enhancements

### Phase 2 Planning
- [ ] Password encryption at rest
- [ ] Password rotation policies
- [ ] Session monitoring and timeout
- [ ] Advanced audit reporting
- [ ] API rate limiting
- [ ] Password strength enforcement
- [ ] Bulk import/export functionality
- [ ] Advanced search with Elasticsearch
- [ ] Mobile-responsive improvements
- [ ] Two-factor authentication

### Security Improvements
- [ ] Password field encryption
- [ ] Certificate-based authentication
- [ ] Advanced session management
- [ ] Automated security scanning
- [ ] Compliance reporting (SOX, PCI, etc.)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For questions, issues, or contributions:
1. Check the documentation
2. Search existing issues
3. Create a new issue with detailed information
4. Contact the development team

---

**Menshun PAM** - Secure, scalable, and enterprise-ready privileged access management with a revolutionary cyberpunk design system.