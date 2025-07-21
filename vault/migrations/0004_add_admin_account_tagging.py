# Generated migration for admin account tagging

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('vault', '0003_add_entra_integration_models'),
    ]

    operations = [
        migrations.AddField(
            model_name='vaultentry',
            name='is_admin_account',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='vaultentry',
            name='admin_account_type',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='vaultentry',
            name='source_integration',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='vaultentry',
            name='tags',
            field=models.JSONField(blank=True, default=list),
        ),
    ]