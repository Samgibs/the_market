# Generated by Django 5.0.6 on 2024-06-20 10:12

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0002_profile'),
    ]

    operations = [
        migrations.AlterField(
            model_name='profile',
            name='role',
            field=models.CharField(choices=[('admin', 'Admin'), ('buyer', 'Buyer'), ('seller', 'Seller')], max_length=10),
        ),
    ]
