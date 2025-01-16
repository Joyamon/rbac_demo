# Generated by Django 4.2.17 on 2025-01-15 03:29

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("accounts", "0013_document_edited_content"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="document",
            name="edited_content",
        ),
        migrations.AddField(
            model_name="customuser",
            name="dingtalk_name",
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name="customuser",
            name="dingtalk_unionid",
            field=models.CharField(blank=True, max_length=100, null=True, unique=True),
        ),
        migrations.AddField(
            model_name="customuser",
            name="dingtalk_userid",
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
    ]