# Generated by Django 3.2.9 on 2022-06-03 06:58

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('manager', '0011_loggerdata'),
    ]

    operations = [
        migrations.AddField(
            model_name='loggerdata',
            name='role',
            field=models.CharField(blank=True, max_length=200, null=True),
        ),
    ]
