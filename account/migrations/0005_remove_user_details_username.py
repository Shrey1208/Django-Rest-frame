# Generated by Django 4.1.10 on 2023-09-08 05:47

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0004_user_details_username'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='user_details',
            name='username',
        ),
    ]
