# Microsoft Entra ID Integration Guide

## Overview

This guide walks you through setting up Microsoft Entra ID (Azure AD) integration with Menshun PAM v2.0. The integration enables automated user management, role assignments, and privileged access control directly from the Menshun interface.

## Features Enabled

- **User Account Management**: Search, create, update, disable/enable Entra users
- **Role Assignments**: Assign directory roles (permanent and PIM eligible)
- **Service Principal Management**: Create and manage app registrations
- **Privileged Identity Management (PIM)**: Manage eligible role assignments
- **Account Synchronization**: Sync Entra users with local Menshun accounts
- **Audit Logging**: Complete audit trail of all Entra operations

## Prerequisites

### Azure Requirements
- Azure AD Premium P1 or P2 license (for PIM features)
- Global Administrator or Application Administrator role
- Access to Azure Portal (portal.azure.com)

### Menshun Requirements
- Menshun PAM v2.0 with Entra integration module
- Superuser access to Menshun admin console
- Network connectivity to Microsoft Graph API (graph.microsoft.com)

## Step 1: Create Azure AD Application Registration

### 1.1 Register the Application

1. **Navigate to Azure Portal**
   - Go to [portal.azure.com](https://portal.azure.com)
   - Sign in with Global Administrator account

2. **Open App Registrations**
   - Navigate to: **Azure Active Directory** → **App registrations**
   - Click **"New registration"**

3. **Configure Application**
   - **Name**: `Menshun PAM Integration`
   - **Supported account types**: `Accounts in this organizational directory only`
   - **Redirect URI**: Leave blank (not needed for daemon apps)
   - Click **Register**

### 1.2 Configure Application Permissions

1. **Navigate to API Permissions**
   - In your app registration, go to **API permissions**
   - Click **"Add a permission"**

2. **Add Microsoft Graph Permissions**
   - Select **Microsoft Graph** → **Application permissions**
   - Add the following permissions:

   **User Management:**
   - `User.Read.All` - Read all user profiles
   - `User.ReadWrite.All` - Read and write all user profiles
   - `Directory.Read.All` - Read directory data
   - `Directory.ReadWrite.All` - Read and write directory data

   **Role Management:**
   - `RoleManagement.Read.All` - Read role management data
   - `RoleManagement.ReadWrite.All` - Read and write role management data
   - `Directory.AccessAsUser.All` - Access directory as signed-in user

   **PIM Management (if using PIM):**
   - `PrivilegedAccess.Read.AzureAD` - Read privileged access to Azure AD
   - `PrivilegedAccess.ReadWrite.AzureAD` - Read and write privileged access to Azure AD

3. **Grant Admin Consent**
   - Click **"Grant admin consent for [Your Organization]"**
   - Confirm by clicking **"Yes"**

### 1.3 Create Client Secret

1. **Navigate to Certificates & secrets**
   - In your app registration, go to **Certificates & secrets**
   - Click **"New client secret"**

2. **Configure Secret**
   - **Description**: `Menshun PAM Client Secret`
   - **Expires**: `24 months` (recommended)
   - Click **Add**

3. **Copy Secret Value**
   - **⚠️ IMPORTANT**: Copy the secret value immediately
   - Store it securely - you won't be able to see it again
   - This is your `CLIENT_SECRET`

### 1.4 Collect Configuration Values

Copy these values for Menshun configuration:

```
TENANT_ID: [Your Azure AD Tenant ID]
CLIENT_ID: [Application (client) ID from app registration]
CLIENT_SECRET: [Client secret value from previous step]
```

**To find your Tenant ID:**
- Azure Portal → Azure Active Directory → Overview → Tenant ID

## Step 2: Configure Menshun Integration

### 2.1 Access Integration Settings

1. **Login to Menshun**
   - Access your Menshun PAM dashboard
   - Ensure you have superuser/admin privileges

2. **Navigate to Integrations**
   - Click **Admin Console** → **Integrations**
   - Or use sidebar: **Administration** → **Integrations**

### 2.2 Configure Entra Integration

1. **Open Entra Configuration**
   - In the Integrations modal, click the **Microsoft Entra** tab
   - You'll see the configuration form

2. **Enter Configuration Values**
   ```
   Tenant ID: [Your Azure AD Tenant ID]
   Client ID: [Application (client) ID]
   Client Secret: [Client secret value]
   ```

3. **Optional Settings**
   - ☑️ **Enable automatic user synchronization** (recommended)
   - This syncs Entra users with local Menshun accounts

4. **Save Configuration**
   - Click **"Save Configuration"**
   - Wait for success confirmation

### 2.3 Test Connection

1. **Test Integration**
   - Click **"Test Connection"** button
   - Wait for test results

2. **Expected Results**
   - ✅ **Success**: "Entra connection test successful!"
   - ❌ **Error**: Check configuration values and permissions

## Step 3: Verify Integration

### 3.1 Check Integration Status

1. **Overview Tab**
   - Return to **Overview** tab in Integrations modal
   - Verify **Microsoft Entra ID** shows "Connected" status
   - Check that **Active Integrations** count increased

### 3.2 Test Basic Operations

1. **User Lookup**
   - Go to **Microsoft Entra** tab
   - Click **"User Lookup"** (when implemented)
   - Search for existing users to verify read access

2. **Check Audit Logs**
   - Navigate to **Admin Console** → **Audit Logs**
   - Look for Entra integration events
   - Verify connection test was logged

## Step 4: Advanced Configuration

### 4.1 Environment Variables (Optional)

For production deployments, you can set environment variables instead of using the UI:

```bash
# Add to your environment or .env file
ENTRA_TENANT_ID=your-tenant-id-here
ENTRA_CLIENT_ID=your-client-id-here
ENTRA_CLIENT_SECRET=your-client-secret-here
```

### 4.2 Database Migration

Ensure integration models are created:

```bash
# Run from Menshun directory
source venv/bin/activate
python manage.py migrate vault
```

## Available Operations

Once configured, you can perform these operations:

### User Management
- 🔍 **Search Users**: Find users by name, email, or UPN
- ➕ **Create Users**: Create new Entra ID accounts
- ✏️ **Update Users**: Modify user properties
- 🚫 **Disable/Enable**: Control account access
- 🗑️ **Delete Users**: Remove accounts (soft delete)

### Role Management
- 👑 **Assign Roles**: Grant directory roles to users
- ⏰ **PIM Eligible**: Create time-bound eligible assignments
- 🔄 **Role Sync**: Synchronize role assignments
- 📋 **List Roles**: View all available directory roles

### Service Principals
- 🤖 **Create Apps**: Register new applications
- 🔑 **Manage Secrets**: Handle client credentials
- 📜 **API Permissions**: Configure application permissions
- 🎯 **Delegated Access**: Set up user delegation

## Security Best Practices

### Application Security
- 🔐 Use certificate authentication when possible
- 🔄 Rotate client secrets regularly (every 12-24 months)
- 📊 Monitor application usage and permissions
- 🛡️ Apply principle of least privilege

### Access Control
- 👥 Limit who can configure integrations
- 📝 Audit all integration activities
- 🚨 Set up alerts for suspicious activities
- 🔒 Use conditional access policies

### Monitoring
- 📈 Monitor API usage and rate limits
- 🚦 Set up health checks and alerts
- 📊 Review audit logs regularly
- 🔍 Track privilege escalations

## Troubleshooting

### Common Issues

**"Insufficient privileges" error:**
- Verify admin consent was granted
- Check that all required permissions are added
- Ensure the user has appropriate Azure AD roles

**"Application not found" error:**
- Verify Tenant ID is correct
- Check that Client ID is correct
- Ensure app registration wasn't deleted

**"Invalid client secret" error:**
- Client secret may have expired
- Generate new client secret
- Update Menshun configuration

**Connection timeouts:**
- Check network connectivity to graph.microsoft.com
- Verify firewall rules allow HTTPS (443) outbound
- Test DNS resolution for Microsoft endpoints

### Getting Help

1. **Check Audit Logs**: Look for detailed error messages
2. **Console Logs**: Check browser developer console for errors
3. **Azure AD Logs**: Review sign-in and audit logs in Azure Portal
4. **Graph Explorer**: Test permissions using [developer.microsoft.com/graph/graph-explorer](https://developer.microsoft.com/graph/graph-explorer)

## API Rate Limits

Microsoft Graph has the following rate limits:

- **User operations**: 3,000 requests per app per tenant per minute
- **Role operations**: 300 requests per app per tenant per minute
- **Large operations**: Consider batching and pagination

Menshun automatically handles rate limiting with exponential backoff.

## Compliance and Governance

### Data Handling
- Menshun caches minimal user data for performance
- All sensitive operations require fresh API calls
- User passwords are never stored or transmitted
- Audit logs maintain complete operation history

### Regulatory Compliance
- GDPR: User data can be purged on request
- SOX: Complete audit trail of privileged access
- HIPAA: Encryption in transit and at rest
- PCI: Privileged access monitoring and control

## Support and Updates

### Version Compatibility
- Menshun PAM v2.0+: Full feature support
- Azure AD Free: Basic user management
- Azure AD Premium P1/P2: Full PIM support

### Feature Roadmap
- 🔄 Real-time user synchronization
- 📊 Advanced analytics and reporting
- 🤖 Automated role lifecycle management
- 🔍 AI-powered access recommendations

---

## Quick Reference

### Essential URLs
- Azure Portal: https://portal.azure.com
- Graph Explorer: https://developer.microsoft.com/graph/graph-explorer
- Microsoft Graph Docs: https://docs.microsoft.com/graph

### Key PowerShell Commands
```powershell
# Connect to Azure AD
Connect-AzureAD

# List app registrations
Get-AzureADApplication -Filter "displayName eq 'Menshun PAM Integration'"

# Check app permissions
Get-AzureADServicePrincipal -Filter "displayName eq 'Menshun PAM Integration'"
```

### Useful Graph API Endpoints
```
GET https://graph.microsoft.com/v1.0/users
GET https://graph.microsoft.com/v1.0/directoryRoles
GET https://graph.microsoft.com/v1.0/applications
```

---

**Next Steps**: Once configured, proceed to implement specific Entra operations like user lookup and role assignment through the Menshun interface.