class Roles:
    """Django group names used for vault role-based access control."""
    ADMIN = 'Vault Admin'
    EDITOR = 'Vault Editor'
    VIEWER = 'Vault Viewer'

    ALL = (ADMIN, EDITOR, VIEWER)
