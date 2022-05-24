# Generated by Django 3.2.9 on 2022-05-24 07:25

from django.db import migrations
import phonenumber_field.modelfields


class Migration(migrations.Migration):

    dependencies = [
        ('manager', '0011_alter_extendedauthuser_role'),
    ]

    operations = [
        migrations.AlterField(
            model_name='extendedauthuser',
            name='phone',
            field=phonenumber_field.modelfields.PhoneNumberField(blank=True, max_length=13, null=True, region=None, unique=True, verbose_name='phone'),
        ),
    ]