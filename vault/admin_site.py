from django.contrib.admin.apps import AdminConfig as DjangoAdminConfig
from django.contrib.admin.sites import AdminSite
from django.shortcuts import redirect


class MenshunAdminSite(AdminSite):
    """
    Django admin is a secondary, low-level tool in this app — the Command
    Center (vault:home) is the intended landing page after any login.
    Overriding just the post-login redirect keeps /admin/ itself fully
    usable for direct model access once already authenticated.
    """

    def login(self, request, extra_context=None):
        response = super().login(request, extra_context)
        if request.method == 'POST' and request.user.is_authenticated:
            return redirect('vault:home')
        return response


class MenshunAdminConfig(DjangoAdminConfig):
    default_site = 'vault.admin_site.MenshunAdminSite'
