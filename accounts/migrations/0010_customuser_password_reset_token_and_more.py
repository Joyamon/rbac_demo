# Generated by Django 4.2.17 on 2025-01-11 07:25

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("accounts", "0009_useractivity_delete_rolepermission"),
    ]

    operations = [
        migrations.AddField(
            model_name="customuser",
            name="password_reset_token",
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name="customuser",
            name="email",
            field=models.EmailField(max_length=254, unique=True),
        ),
    ]
