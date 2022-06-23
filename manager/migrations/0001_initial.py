# Generated by Django 3.2.9 on 2022-06-23 20:50

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone
import manager.models
import phonenumber_field.modelfields


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='CustomerFields',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('quote_contact', models.CharField(blank=True, max_length=200, null=True)),
                ('quote_phone', phonenumber_field.modelfields.PhoneNumberField(blank=True, max_length=13, null=True, region=None, verbose_name='phone')),
                ('quote_email', models.CharField(blank=True, max_length=100, null=True)),
                ('quote_wechat', models.CharField(blank=True, max_length=200, null=True)),
                ('pickup_select', models.CharField(blank=True, max_length=100, null=True)),
                ('pickup_address', models.CharField(blank=True, max_length=100, null=True)),
                ('zipcode', models.CharField(blank=True, max_length=100, null=True)),
                ('internal_order_number', models.CharField(blank=True, max_length=200, null=True)),
                ('pickup_contact_phone', phonenumber_field.modelfields.PhoneNumberField(blank=True, max_length=13, null=True, region=None, verbose_name='phone')),
                ('pickup_contact', models.CharField(blank=True, max_length=100, null=True)),
                ('pickup_contact_email', models.CharField(blank=True, max_length=100, null=True)),
                ('shipping_select', models.CharField(blank=True, max_length=100, null=True)),
                ('shipping_address', models.CharField(blank=True, max_length=100, null=True)),
                ('shipping_zipcode', models.CharField(blank=True, max_length=100, null=True)),
                ('shipping_order_number', models.CharField(blank=True, max_length=100, null=True)),
                ('shipping_contact', models.CharField(blank=True, max_length=100, null=True)),
                ('shipping_contact_phone', phonenumber_field.modelfields.PhoneNumberField(blank=True, max_length=13, null=True, region=None, verbose_name='phone')),
                ('shipping_contact_email', models.CharField(blank=True, max_length=100, null=True)),
                ('item_name', models.CharField(blank=True, max_length=100, null=True)),
                ('prefix', models.CharField(blank=True, max_length=100, null=True)),
                ('packaging_board', models.CharField(blank=True, max_length=100, null=True)),
                ('dimensions', models.CharField(blank=True, max_length=100, null=True)),
                ('weight', models.CharField(blank=True, max_length=100, null=True)),
                ('payer', models.CharField(blank=True, max_length=100, null=True)),
                ('media', models.FileField(blank=True, null=True, upload_to='customer/')),
                ('modified_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
            ],
            options={
                'verbose_name_plural': 'customerfields',
                'db_table': 'customerfields',
                'ordering': ('created_at',),
            },
        ),
        migrations.CreateModel(
            name='DoIncomingsModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('pdf', models.FileField(blank=True, null=True, upload_to='uploads/')),
                ('cntr', models.CharField(blank=True, max_length=200, null=True)),
                ('mbl', models.CharField(blank=True, max_length=200, null=True)),
                ('seal', models.CharField(blank=True, max_length=200, null=True)),
                ('ship', models.CharField(blank=True, max_length=255, null=True)),
                ('size', models.CharField(blank=True, max_length=100, null=True)),
                ('weight', models.CharField(blank=True, max_length=100, null=True)),
                ('type', models.CharField(blank=True, max_length=100, null=True)),
                ('port', models.CharField(blank=True, max_length=100, null=True)),
                ('eta', models.CharField(blank=True, max_length=100, null=True)),
                ('drop_city', models.CharField(blank=True, max_length=100, null=True)),
                ('file_size', models.CharField(max_length=100, null=True)),
                ('file_type', models.CharField(max_length=100, null=True)),
                ('modified_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
            ],
            options={
                'verbose_name_plural': 'doincomings',
                'db_table': 'doincomings',
                'ordering': ('created_at',),
            },
        ),
        migrations.CreateModel(
            name='ExtendedAdmin',
            fields=[
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, primary_key=True, serialize=False, to='auth.user')),
                ('location', models.CharField(blank=True, max_length=100, null=True)),
                ('main', models.BooleanField(default=False)),
                ('is_installed', models.BooleanField(default=False)),
            ],
            options={
                'verbose_name_plural': 'extended_admins',
                'db_table': 'extended_admin',
            },
        ),
        migrations.CreateModel(
            name='ExtendedAuthUser',
            fields=[
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, primary_key=True, serialize=False, to='auth.user')),
                ('phone', phonenumber_field.modelfields.PhoneNumberField(blank=True, max_length=13, null=True, region=None, unique=True, verbose_name='phone')),
                ('initials', models.CharField(blank=True, max_length=10, null=True)),
                ('bgcolor', models.CharField(blank=True, default=manager.models.bgcolor, max_length=10, null=True)),
                ('company', models.CharField(blank=True, default='Armlogi', max_length=100, null=True)),
                ('profile_pic', models.ImageField(blank=True, default='placeholder.jpg', null=True, upload_to='profiles/')),
                ('role', models.CharField(blank=True, choices=[('Tertiary', 'View only'), ('Secondary', 'View | Edit'), ('Admin', 'View | Edit  | Admin')], max_length=200, null=True)),
                ('created_on', models.DateTimeField(default=django.utils.timezone.now)),
            ],
            options={
                'verbose_name_plural': 'extended_auth_users',
                'db_table': 'extended_auth_user',
                'permissions': (('can_view', 'Can view'), ('can_edit', 'Can edit'), ('can_see_invoice', 'Can see invoice')),
            },
        ),
        migrations.CreateModel(
            name='Logger',
            fields=[
                ('log_id', models.BigAutoField(primary_key=True, serialize=False)),
                ('action', models.CharField(blank=True, max_length=200, null=True)),
                ('user', models.CharField(blank=True, max_length=200, null=True)),
                ('role', models.CharField(blank=True, max_length=200, null=True)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
            ],
            options={
                'verbose_name_plural': 'data_logger',
                'db_table': 'data_logger',
            },
        ),
        migrations.CreateModel(
            name='OrderLogData',
            fields=[
                ('log_id', models.BigAutoField(primary_key=True, serialize=False)),
                ('ordername', models.CharField(max_length=50, null=True, verbose_name='ordername')),
                ('order_id', models.IntegerField(blank=True, null=True)),
                ('action', models.CharField(blank=True, max_length=200, null=True)),
                ('user', models.CharField(blank=True, max_length=200, null=True)),
                ('role', models.CharField(blank=True, max_length=200, null=True)),
                ('status', models.CharField(blank=True, max_length=255, null=True)),
                ('pierpass', models.CharField(blank=True, max_length=100, null=True)),
                ('pierpass_dolla', models.CharField(blank=True, max_length=100, null=True)),
                ('exam', models.CharField(blank=True, max_length=100, null=True)),
                ('ship_to', models.CharField(blank=True, max_length=100, null=True)),
                ('full_out_driver', models.CharField(blank=True, max_length=100, null=True)),
                ('empty_in_driver', models.CharField(blank=True, max_length=100, null=True)),
                ('demurrage_dolla', models.CharField(blank=True, max_length=100, null=True)),
                ('per_diem', models.CharField(blank=True, max_length=100, null=True)),
                ('sml', models.CharField(blank=True, max_length=100, null=True)),
                ('column_33', models.CharField(blank=True, max_length=100, null=True)),
                ('do_recd', models.CharField(blank=True, max_length=100, null=True)),
                ('mbl', models.CharField(blank=True, max_length=100, null=True)),
                ('hbl', models.CharField(blank=True, max_length=100, null=True)),
                ('customer', models.CharField(blank=True, max_length=100, null=True)),
                ('container', models.CharField(blank=True, max_length=100, null=True)),
                ('type', models.CharField(blank=True, max_length=100, null=True)),
                ('seal', models.CharField(blank=True, max_length=100, null=True)),
                ('drop_city', models.CharField(blank=True, max_length=100, null=True)),
                ('discharge_port', models.CharField(blank=True, max_length=100, null=True)),
                ('port_eta', models.CharField(blank=True, max_length=100, null=True)),
                ('lfd', models.CharField(blank=True, max_length=100, null=True)),
                ('trucking', models.CharField(blank=True, max_length=100, null=True)),
                ('east_deliver', models.CharField(blank=True, max_length=100, null=True)),
                ('appointment', models.CharField(blank=True, max_length=100, null=True)),
                ('actual_deliver', models.CharField(blank=True, max_length=100, null=True)),
                ('driver', models.CharField(blank=True, max_length=100, null=True)),
                ('empty_return', models.CharField(blank=True, max_length=100, null=True)),
                ('chasis', models.CharField(blank=True, max_length=100, null=True)),
                ('demurrage', models.CharField(blank=True, max_length=100, null=True)),
                ('invoice_sent', models.CharField(blank=True, max_length=100, null=True)),
                ('invoice', models.CharField(blank=True, max_length=100, null=True)),
                ('invoice_dolla', models.CharField(blank=True, max_length=100, null=True)),
                ('a_rrry', models.CharField(blank=True, max_length=100, null=True)),
                ('a_ppy', models.CharField(blank=True, max_length=100, null=True)),
                ('customer_email', models.CharField(blank=True, max_length=100, null=True)),
                ('notify', models.CharField(blank=True, max_length=100, null=True)),
                ('prefix', models.CharField(blank=True, max_length=100, null=True)),
                ('acct_email', models.CharField(max_length=100, null=True)),
                ('comment', models.TextField(blank=True, null=True)),
                ('media', models.CharField(blank=True, max_length=100, null=True)),
                ('date', models.DateField(blank=True, null=True)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
            ],
            options={
                'verbose_name_plural': 'order_logger_data',
                'db_table': 'order_logger_data',
            },
        ),
        migrations.CreateModel(
            name='OrderModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ordername_serial', models.CharField(default=manager.models.generate_serial, max_length=255)),
                ('ordername', models.CharField(max_length=50, null=True, verbose_name='ordername')),
                ('load', models.CharField(default=manager.models.generate_id, max_length=100)),
                ('action', models.CharField(blank=True, max_length=200, null=True)),
                ('user', models.CharField(blank=True, max_length=200, null=True)),
                ('role', models.CharField(blank=True, max_length=200, null=True)),
                ('status', models.CharField(blank=True, max_length=255, null=True)),
                ('pierpass', models.CharField(blank=True, max_length=100, null=True)),
                ('pierpass_dolla', models.CharField(blank=True, max_length=100, null=True)),
                ('exam', models.CharField(blank=True, max_length=100, null=True)),
                ('ship_to', models.CharField(blank=True, max_length=100, null=True)),
                ('full_out_driver', models.CharField(blank=True, max_length=100, null=True)),
                ('empty_in_driver', models.CharField(blank=True, max_length=100, null=True)),
                ('demurrage_dolla', models.CharField(blank=True, max_length=100, null=True)),
                ('per_diem', models.CharField(blank=True, max_length=100, null=True)),
                ('sml', models.CharField(blank=True, max_length=100, null=True)),
                ('column_33', models.CharField(blank=True, max_length=100, null=True)),
                ('do_recd', models.CharField(blank=True, max_length=100, null=True)),
                ('mbl', models.CharField(blank=True, max_length=100, null=True)),
                ('hbl', models.CharField(blank=True, max_length=100, null=True)),
                ('customer', models.CharField(blank=True, max_length=100, null=True)),
                ('container', models.CharField(blank=True, max_length=100, null=True)),
                ('type', models.CharField(blank=True, max_length=100, null=True)),
                ('seal', models.CharField(blank=True, max_length=100, null=True)),
                ('drop_city', models.CharField(blank=True, max_length=100, null=True)),
                ('discharge_port', models.CharField(blank=True, max_length=100, null=True)),
                ('port_eta', models.CharField(blank=True, max_length=100, null=True)),
                ('lfd', models.CharField(blank=True, max_length=100, null=True)),
                ('trucking', models.CharField(blank=True, max_length=100, null=True)),
                ('east_deliver', models.CharField(blank=True, max_length=100, null=True)),
                ('appointment', models.CharField(blank=True, max_length=100, null=True)),
                ('actual_deliver', models.CharField(blank=True, max_length=100, null=True)),
                ('driver', models.CharField(blank=True, max_length=100, null=True)),
                ('empty_return', models.CharField(blank=True, max_length=100, null=True)),
                ('chasis', models.CharField(blank=True, max_length=100, null=True)),
                ('demurrage', models.CharField(blank=True, max_length=100, null=True)),
                ('invoice_sent', models.CharField(blank=True, max_length=100, null=True)),
                ('invoice', models.CharField(blank=True, max_length=100, null=True)),
                ('invoice_dolla', models.CharField(blank=True, max_length=100, null=True)),
                ('a_rrry', models.CharField(blank=True, max_length=100, null=True)),
                ('a_ppy', models.CharField(blank=True, max_length=100, null=True)),
                ('customer_email', models.CharField(blank=True, max_length=100, null=True)),
                ('notify', models.CharField(blank=True, max_length=100, null=True)),
                ('prefix', models.CharField(blank=True, max_length=100, null=True)),
                ('acct_email', models.CharField(max_length=100, null=True)),
                ('customer_link', models.CharField(default=manager.models.generate_serial, max_length=100, null=True)),
                ('comment', models.TextField(blank=True, null=True)),
                ('media', models.FileField(blank=True, default='', null=True, upload_to='uploads/')),
                ('file_size', models.CharField(max_length=100, null=True)),
                ('file_type', models.CharField(max_length=100, null=True)),
                ('date', models.DateField(blank=True, null=True)),
                ('modified_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
            ],
            options={
                'verbose_name_plural': 'customer_orders',
                'db_table': 'customer_orders',
                'ordering': ('modified_at', 'prefix'),
            },
        ),
        migrations.CreateModel(
            name='UserFileUploads',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('media', models.FileField(blank=True, null=True, upload_to='uploads/')),
                ('order_indentity', models.CharField(blank=True, max_length=100, null=True)),
                ('ordername', models.CharField(blank=True, max_length=100, null=True)),
                ('uploaded_on', models.DateTimeField(default=django.utils.timezone.now)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name_plural': 'user_file_uploads',
                'db_table': 'user_file_uploads',
            },
        ),
    ]
