# Generated by Django 4.1.10 on 2023-09-08 04:48

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0002_user_details_user'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='user_details',
            name='User',
        ),
        migrations.RemoveField(
            model_name='user_details',
            name='username',
        ),
    ]
