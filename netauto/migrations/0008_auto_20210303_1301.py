# Generated by Django 3.0.1 on 2021-03-03 06:01

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('netauto', '0007_auto_20210303_1248'),
    ]

    operations = [
        migrations.AlterField(
            model_name='attacklog',
            name='acl_sequence',
            field=models.IntegerField(),
        ),
    ]