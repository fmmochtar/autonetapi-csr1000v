# Generated by Django 3.0.3 on 2020-04-06 08:26

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('netauto', '0005_device_scripts'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='device',
            name='scripts',
        ),
        migrations.AddField(
            model_name='log',
            name='user',
            field=models.CharField(default='Anonymous', max_length=200),
        ),
    ]
