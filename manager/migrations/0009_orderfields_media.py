# Generated by Django 3.2.9 on 2022-05-20 20:26

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('manager', '0008_userfileuploads_order_indentity'),
    ]

    operations = [
        migrations.AddField(
            model_name='orderfields',
            name='media',
            field=models.FileField(blank=True, null=True, upload_to='uploads/'),
        ),
    ]
