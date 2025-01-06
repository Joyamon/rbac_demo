# Generated by Django 4.2.17 on 2025-01-06 02:16

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("auth", "0012_alter_user_first_name_max_length"),
        ("accounts", "0007_rolepermission"),
    ]

    operations = [
        migrations.AlterField(
            model_name="customuser",
            name="groups",
            field=models.ManyToManyField(
                blank=True,
                related_name="customuser_set",
                related_query_name="customuser",
                to="auth.group",
                verbose_name="groups",
            ),
        ),
        migrations.AlterField(
            model_name="customuser",
            name="user_permissions",
            field=models.ManyToManyField(
                blank=True,
                related_name="customuser_set",
                related_query_name="customuser",
                to="auth.permission",
                verbose_name="user permissions",
            ),
        ),
    ]
