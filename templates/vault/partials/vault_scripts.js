// Modal Management
function openAddEntryModal() {
    document.getElementById('addEntryModal').style.display = 'block';
    document.body.style.overflow = 'hidden';
    // Focus first input
    setTimeout(() => {
        document.querySelector('#addEntryForm input[name="name"]').focus();
    }, 100);
}

function closeAddEntryModal() {
    document.getElementById('addEntryModal').style.display = 'none';
    document.body.style.overflow = 'auto';
    // Reset form
    document.getElementById('addEntryForm').reset();
}

function openEditEntryModal() {
    document.getElementById('editEntryModal').style.display = 'block';
    document.body.style.overflow = 'hidden';
}

function closeEditEntryModal() {
    document.getElementById('editEntryModal').style.display = 'none';
    document.body.style.overflow = 'auto';
    // Reset form
    document.getElementById('editEntryForm').reset();
}

function closeViewPasswordModal() {
    document.getElementById('viewPasswordModal').style.display = 'none';
    document.body.style.overflow = 'auto';
    // Reset password display
    document.getElementById('passwordDisplay').textContent = '••••••••••••';
    document.getElementById('modalToggleText').textContent = 'Show';
    document.getElementById('modalToggleIcon').className = 'ph ph-eye';
}

// Password Management
function togglePasswordVisibility(formId) {
    const form = document.getElementById(formId);
    const passwordInput = form.querySelector('input[name="password"]');
    const toggleIcon = form.querySelector('#passwordToggleIcon') || form.querySelector('.ph-eye, .ph-eye-slash');
    
    if (passwordInput.type === 'password') {
        passwordInput.type = 'text';
        if (toggleIcon) toggleIcon.className = 'ph ph-eye-slash';
    } else {
        passwordInput.type = 'password';
        if (toggleIcon) toggleIcon.className = 'ph ph-eye';
    }
}

function generatePassword(formId) {
    const form = document.getElementById(formId);
    const passwordInput = form.querySelector('input[name="password"]');
    
    // Generate a secure password
    const length = 16;
    const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
    let password = '';
    
    for (let i = 0; i < length; i++) {
        password += charset.charAt(Math.floor(Math.random() * charset.length));
    }
    
    passwordInput.value = password;
    passwordInput.type = 'text'; // Show generated password
    
    // Update toggle icon
    const toggleIcon = form.querySelector('#passwordToggleIcon') || form.querySelector('.ph-eye, .ph-eye-slash');
    if (toggleIcon) toggleIcon.className = 'ph ph-eye-slash';
}

let currentPassword = '';

function viewPassword(entryId, entryName) {
    console.log('viewPassword called for entry:', entryId, entryName);  // Debug log
    
    // Fetch the actual password from the server
    fetch(`/ajax/vault-entry/${entryId}/get/`, {
        method: 'GET',
        headers: {
            'X-CSRFToken': getCSRFToken(),
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            currentPassword = data.data.password;
            
            document.getElementById('passwordEntryName').textContent = entryName;
            document.getElementById('passwordDisplay').textContent = '••••••••••••';
            document.getElementById('modalToggleText').textContent = 'Show';
            document.getElementById('modalToggleIcon').className = 'ph ph-eye';
            
            document.getElementById('viewPasswordModal').style.display = 'block';
            document.body.style.overflow = 'hidden';
        } else {
            showNotification(data.error || 'Failed to load vault entry', 'error');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showNotification('An unexpected error occurred', 'error');
    });
}

function togglePasswordInModal() {
    const passwordDisplay = document.getElementById('passwordDisplay');
    const toggleText = document.getElementById('modalToggleText');
    const toggleIcon = document.getElementById('modalToggleIcon');
    
    if (passwordDisplay.textContent === '••••••••••••') {
        passwordDisplay.textContent = currentPassword;
        toggleText.textContent = 'Hide';
        toggleIcon.className = 'ph ph-eye-slash';
    } else {
        passwordDisplay.textContent = '••••••••••••';
        toggleText.textContent = 'Show';
        toggleIcon.className = 'ph ph-eye';
    }
}

function copyPassword() {
    const copyIcon = document.getElementById('copyIcon');
    
    // Copy to clipboard
    navigator.clipboard.writeText(currentPassword).then(() => {
        // Visual feedback
        copyIcon.className = 'ph ph-check';
        copyIcon.style.color = 'var(--emerald-green)';
        
        setTimeout(() => {
            copyIcon.className = 'ph ph-copy';
            copyIcon.style.color = 'var(--electric-blue)';
        }, 2000);
    }).catch(() => {
        // Fallback for older browsers
        const textArea = document.createElement('textarea');
        textArea.value = currentPassword;
        document.body.appendChild(textArea);
        textArea.select();
        document.execCommand('copy');
        document.body.removeChild(textArea);
        
        // Visual feedback
        copyIcon.className = 'ph ph-check';
        copyIcon.style.color = 'var(--emerald-green)';
        
        setTimeout(() => {
            copyIcon.className = 'ph ph-copy';
            copyIcon.style.color = 'var(--electric-blue)';
        }, 2000);
    });
}

function editEntry(entryId) {
    // Fetch real entry data from the server
    fetch(`/ajax/vault-entry/${entryId}/get/`, {
        method: 'GET',
        headers: {
            'X-CSRFToken': getCSRFToken(),
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Populate the form with real data
            document.getElementById('editEntryId').value = data.data.id;
            document.getElementById('editEntryName').value = data.data.name;
            document.getElementById('editEntryUsername').value = data.data.username;
            document.getElementById('editEntryPassword').value = data.data.password;
            document.getElementById('editEntryCredentialType').value = data.data.credential_type;
            document.getElementById('editEntryUrl').value = data.data.url;
            document.getElementById('editEntryNotes').value = data.data.notes;
            
            openEditEntryModal();
        } else {
            showNotification(data.error || 'Failed to load vault entry', 'error');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showNotification('An unexpected error occurred', 'error');
    });
}

// CSRF Token Helper - Get from form input or cookie
function getCSRFToken() {
    // First try to get from any form's hidden input
    const formToken = document.querySelector('[name=csrfmiddlewaretoken]');
    if (formToken) {
        return formToken.value;
    }
    
    // Fallback to cookie
    const name = 'csrftoken';
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

// Show notification
function showNotification(message, type = 'success') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `card message-${type}`;
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        z-index: 2000;
        min-width: 300px;
        max-width: 500px;
        margin-bottom: var(--space-md);
        animation: slideIn 0.3s ease-out;
    `;
    
    const icon = type === 'success' ? 'check-circle' : 
                 type === 'error' ? 'warning-circle' : 'info';
    
    notification.innerHTML = `
        <i class="ph ph-${icon}" style="margin-right: var(--space-xs);"></i>
        ${message}
    `;
    
    document.body.appendChild(notification);
    
    // Remove after 5 seconds
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease-in';
        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 300);
    }, 5000);
}

// Add CSS for notifications
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }
`;
document.head.appendChild(style);

// Form Submission
document.addEventListener('DOMContentLoaded', function() {
    // Add Entry Form
    const addEntryForm = document.getElementById('addEntryForm');
    if (addEntryForm) {
        addEntryForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const formData = new FormData(this);
            const data = Object.fromEntries(formData);
            
            // Show loading state
            const submitButton = this.querySelector('button[type="submit"]');
            const originalText = submitButton.innerHTML;
            submitButton.innerHTML = '<i class="ph ph-spinner" style="animation: spin 1s linear infinite; margin-right: var(--space-xs);"></i>Creating...';
            submitButton.disabled = true;
            
            // Send AJAX request
            fetch('/ajax/vault-entry/create/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': getCSRFToken(),
                },
                body: JSON.stringify(data)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showNotification(data.message, 'success');
                    closeAddEntryModal();
                    // Refresh the page to show the new entry
                    setTimeout(() => window.location.reload(), 1000);
                } else {
                    if (data.errors) {
                        // Display form validation errors
                        let errorMessage = 'Please fix the following errors:\n';
                        Object.entries(data.errors).forEach(([field, errors]) => {
                            errorMessage += `${field}: ${errors.join(', ')}\n`;
                        });
                        showNotification(errorMessage, 'error');
                    } else {
                        showNotification(data.error || 'Failed to create vault entry', 'error');
                    }
                }
            })
            .catch(error => {
                console.error('Error:', error);
                showNotification('An unexpected error occurred', 'error');
            })
            .finally(() => {
                // Restore button state
                submitButton.innerHTML = originalText;
                submitButton.disabled = false;
            });
        });
    }
    
    // Edit Entry Form
    const editEntryForm = document.getElementById('editEntryForm');
    if (editEntryForm) {
        editEntryForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const formData = new FormData(this);
            const data = Object.fromEntries(formData);
            const entryId = data.entry_id;
            
            // Show loading state
            const submitButton = this.querySelector('button[type="submit"]');
            const originalText = submitButton.innerHTML;
            submitButton.innerHTML = '<i class="ph ph-spinner" style="animation: spin 1s linear infinite; margin-right: var(--space-xs);"></i>Saving...';
            submitButton.disabled = true;
            
            // Send AJAX request
            fetch(`/ajax/vault-entry/${entryId}/update/`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': getCSRFToken(),
                },
                body: JSON.stringify(data)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showNotification(data.message, 'success');
                    closeEditEntryModal();
                    // Refresh the page to show the updated entry
                    setTimeout(() => window.location.reload(), 1000);
                } else {
                    if (data.errors) {
                        // Display form validation errors
                        let errorMessage = 'Please fix the following errors:\n';
                        Object.entries(data.errors).forEach(([field, errors]) => {
                            errorMessage += `${field}: ${errors.join(', ')}\n`;
                        });
                        showNotification(errorMessage, 'error');
                    } else {
                        showNotification(data.error || 'Failed to update vault entry', 'error');
                    }
                }
            })
            .catch(error => {
                console.error('Error:', error);
                showNotification('An unexpected error occurred', 'error');
            })
            .finally(() => {
                // Restore button state
                submitButton.innerHTML = originalText;
                submitButton.disabled = false;
            });
        });
    }
    
    // Close modals when clicking outside
    ['addEntryModal', 'editEntryModal', 'viewPasswordModal'].forEach(modalId => {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.addEventListener('click', function(e) {
                if (e.target === modal) {
                    if (modalId === 'addEntryModal') closeAddEntryModal();
                    else if (modalId === 'editEntryModal') closeEditEntryModal();
                    else if (modalId === 'viewPasswordModal') closeViewPasswordModal();
                }
            });
        }
    });
    
    // Escape key to close modals
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            closeAddEntryModal();
            closeEditEntryModal();
            closeViewPasswordModal();
        }
    });
});