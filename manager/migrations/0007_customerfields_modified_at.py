# Generated by Django 3.2.9 on 2022-06-02 11:44

from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('manager', '0006_customerfields'),
    ]

    operations = [
        migrations.AddField(
            model_name='customerfields',
            name='modified_at',
            field=models.DateTimeField(default=django.utils.timezone.now),
        ),
    ]
