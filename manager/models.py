from django.db import models
from django.contrib.auth.models import User
from django.utils.timezone import now
from django.db.models.signals import post_save,pre_save
from django.dispatch import receiver
from manager.addons import send_email
import random
from django.utils.crypto import get_random_string
from phonenumber_field.modelfields import PhoneNumberField
from django.db.models import Max

class ExtendedAdmin(models.Model):
    user=models.OneToOneField(User,primary_key=True,on_delete=models.CASCADE)
    location=models.CharField(null=True,blank=True,max_length=100)
    main=models.BooleanField(default=False)
    is_installed=models.BooleanField(default=False)

    class Meta:
        db_table='extended_admin'
        verbose_name_plural='extended_admins'

    def __str__(self):
        return f'{self.user.username} site extended admin'
        
#generate random
def generate_id():
    return get_random_string(6,'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKMNOPQRSTUVWXYZ0123456789')


@receiver(post_save, sender=ExtendedAdmin)
def send_installation_email(sender, instance, created, **kwargs):
    if created:
        if instance.is_installed:
            #site is installed
            subject='Congragulations:Site installed successfully.'
            email=instance.user.email
            message={
                        'user':instance.user,
                        'site_name':instance.user.siteconstants.site_name,
                        'site_url':instance.user.siteconstants.site_url
                    }
            template='emails/installation.html'
            send_email(subject,email,message,template)




def bgcolor():
    hex_digits=['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']
    digit_array=[]
    for i in range(6):
        digits=hex_digits[random.randint(0,15)]
        digit_array.append(digits)
    joined_digits=''.join(digit_array)
    color='#'+joined_digits
    return color

user_roles=[
            ('Tertiary','View only'),
            ('Secondary','View | Edit'),
            ('Admin','View | Edit  | Admin'),
        ]


class ExtendedAuthUser(models.Model):
    user=models.OneToOneField(User,primary_key=True,on_delete=models.CASCADE)
    phone=PhoneNumberField(null=True,blank=True,verbose_name='phone',unique=True,max_length=13)
    initials=models.CharField(max_length=10,blank=True,null=True)
    bgcolor=models.CharField(max_length=10,blank=True,null=True,default=bgcolor)
    company=models.CharField(max_length=100,null=True,blank=True,default='Armlogi')
    profile_pic=models.ImageField(upload_to='profiles/',null=True,blank=True,default="placeholder.jpg")
    role=models.CharField(choices=user_roles,max_length=200,null=True,blank=True)
    created_on=models.DateTimeField(default=now)
    class Meta:
        db_table='extended_auth_user'
        verbose_name_plural='extended_auth_users'
        permissions=(
            ("can_view","Can view"),
            ("can_edit","Can edit"),
            ("can_see_invoice","Can see invoice"),
        )
    def __str__(self)->str:
        return f'{self.user.username} extended auth profile'




#generate random
def generate_serial():
    return get_random_string(12,'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKMNOPQRSTUVWXYZ0123456789')
    
class Oders(models.Model):
    ordername_id=models.AutoField(primary_key=True)
    action=models.CharField(null=True,blank=True,max_length=200)
    user=models.CharField(null=True,blank=True,max_length=200)
    role=models.CharField(null=True,blank=True,max_length=200)
    ordername_serial=models.CharField(max_length=255,default=generate_serial)
    ordername=models.CharField(max_length=50,verbose_name='ordername',null=True)
    date=models.DateTimeField(auto_now_add=True)
    class Meta:
        db_table='orders'
        verbose_name_plural='orders'
    def __str__(self)->str:
        return self.ordername

    
@receiver(post_save, sender=Oders)
def create_order_id(sender, instance, created, **kwargs):
    if created:
        op=str(instance.ordername_id).zfill(5)
        prefix='21A'+op
        OrderFields.objects.create(order_id=instance.ordername_id,prefix=prefix,user=instance.user,action=instance.action,role=instance.role)

def save_order_id(sender, instance, *args,**kwargs):
    instance.orderfields.save()
 


class LoggerData(models.Model):
    action=models.CharField(null=True,blank=True,max_length=200)
    user=models.CharField(null=True,blank=True,max_length=200)
    role=models.CharField(null=True,blank=True,max_length=200)
    created_at=models.DateTimeField(default=now)
    class Meta:
        db_table='logger_data'
        verbose_name_plural='logger_data'

    def __str__(self):
        return f'{self.user} logged data'

class OrderLogs(models.Model):
    order_id=models.IntegerField(null=True,blank=True)
    action=models.CharField(null=True,blank=True,max_length=200)
    user=models.CharField(null=True,blank=True,max_length=200)
    role=models.CharField(null=True,blank=True,max_length=200)
    status=models.CharField(max_length=255,null=True,blank=True)
    pierpass=models.CharField(max_length=100,null=True,blank=True)
    mbl=models.CharField(max_length=100,null=True,blank=True)
    hbl=models.CharField(max_length=100,null=True,blank=True)
    customer=models.CharField(max_length=100,null=True,blank=True)
    container=models.CharField(max_length=100,null=True,blank=True)
    type=models.CharField(max_length=100,null=True,blank=True)
    seal=models.CharField(max_length=100,null=True,blank=True)
    drop_city=models.CharField(max_length=100,null=True,blank=True)
    discharge_port=models.CharField(max_length=100,null=True,blank=True)
    port_eta=models.CharField(max_length=100,null=True,blank=True)
    lfd=models.CharField(max_length=100,null=True,blank=True)
    trucking=models.CharField(max_length=100,null=True,blank=True)
    east_deliver=models.CharField(max_length=100,null=True,blank=True)
    appointment=models.CharField(max_length=100,null=True,blank=True)
    actual_deliver=models.CharField(max_length=100,null=True,blank=True)
    driver=models.CharField(max_length=100,null=True,blank=True)
    empty_return=models.CharField(max_length=100,null=True,blank=True)
    chasis=models.CharField(max_length=100,null=True,blank=True)
    demurrage=models.CharField(max_length=100,null=True,blank=True)
    invoice_sent=models.CharField(max_length=100,null=True,blank=True)
    invoice=models.CharField(max_length=100,null=True,blank=True)
    invoice_dolla=models.CharField(max_length=100,null=True,blank=True)
    a_rrry=models.CharField(max_length=100,null=True,blank=True)
    a_ppy=models.CharField(max_length=100,null=True,blank=True)
    customer_email=models.CharField(max_length=100,null=True,blank=True)
    notify=models.CharField(max_length=100,null=True,blank=True)
    prefix=models.CharField(max_length=100,null=True,blank=True)
    acct_email=models.CharField(max_length=100,null=True)
    comment=models.TextField(null=True,blank=True)
    media=models.CharField(max_length=100,null=True,blank=True)
    date=models.DateField(null=True,blank=True)
    created_at=models.DateTimeField(default=now)
    class Meta:
        db_table='order_logs'
        verbose_name_plural='order_logs'

    def __str__(self):
        return f'{self.user} order logs'


options=[
            ("Cancelled pickup","Cancelled pickup"),
            ("On ship","On ship"),
            ("Invoice sent","Invoice sent"),
            ("closed area","Closed area"),
            ("Assigned driver","Assigned driver"),
            ("Delivered","Delivered"),
            ("Do recd","Do Recd"),
        ]
class OrderFields(models.Model):
    order=models.ForeignKey(Oders,on_delete=models.CASCADE)
    load=models.CharField(max_length=100,default=generate_id)
    action=models.CharField(null=True,blank=True,max_length=200)
    user=models.CharField(null=True,blank=True,max_length=200)
    role=models.CharField(null=True,blank=True,max_length=200)
    status=models.CharField(max_length=255,null=True,blank=True)
    pierpass=models.CharField(max_length=100,null=True,blank=True)
    mbl=models.CharField(max_length=100,null=True,blank=True)
    hbl=models.CharField(max_length=100,null=True,blank=True)
    customer=models.CharField(max_length=100,null=True,blank=True)
    container=models.CharField(max_length=100,null=True,blank=True)
    type=models.CharField(max_length=100,null=True,blank=True)
    seal=models.CharField(max_length=100,null=True,blank=True)
    drop_city=models.CharField(max_length=100,null=True,blank=True)
    discharge_port=models.CharField(max_length=100,null=True,blank=True)
    port_eta=models.CharField(max_length=100,null=True,blank=True)
    lfd=models.CharField(max_length=100,null=True,blank=True)
    trucking=models.CharField(max_length=100,null=True,blank=True)
    east_deliver=models.CharField(max_length=100,null=True,blank=True)
    appointment=models.CharField(max_length=100,null=True,blank=True)
    actual_deliver=models.CharField(max_length=100,null=True,blank=True)
    driver=models.CharField(max_length=100,null=True,blank=True)
    empty_return=models.CharField(max_length=100,null=True,blank=True)
    chasis=models.CharField(max_length=100,null=True,blank=True)
    demurrage=models.CharField(max_length=100,null=True,blank=True)
    invoice_sent=models.CharField(max_length=100,null=True,blank=True)
    invoice=models.CharField(max_length=100,null=True,blank=True)
    invoice_dolla=models.CharField(max_length=100,null=True,blank=True)
    a_rrry=models.CharField(max_length=100,null=True,blank=True)
    a_ppy=models.CharField(max_length=100,null=True,blank=True)
    customer_email=models.CharField(max_length=100,null=True,blank=True)
    notify=models.CharField(max_length=100,null=True,blank=True)
    prefix=models.CharField(max_length=100,null=True,blank=True)
    acct_email=models.CharField(max_length=100,null=True)
    customer_link=models.CharField(max_length=100,null=True,default=generate_serial)
    comment=models.TextField(null=True,blank=True)
    media=models.FileField(upload_to='uploads/',null=True,blank=True,default='')
    file_size=models.CharField(max_length=100,null=True)
    file_type=models.CharField(max_length=100,null=True)
    date=models.DateField(null=True,blank=True)
    modified_at=models.DateTimeField(default=now)
    created_at=models.DateTimeField(default=now)
    class Meta:
        db_table='orderfields'
        verbose_name_plural='orderfields'
        ordering=('modified_at','prefix')
    def __str__(self)->str:
        return self.order.ordername

    def delete(self, using=None,keep_parents=False):
        if self.media:
            self.media.storage.delete(self.media.name)
        super().delete()
    @property
    def get_prefix(self):
        return 'A21'+str(self.id).zfill(5)





#uploads
class UserFileUploads(models.Model):
    user=models.ForeignKey(User,on_delete=models.CASCADE)
    media=models.FileField(upload_to='uploads/',null=True,blank=True)
    order_indentity=models.CharField(max_length=100,null=True,blank=True)
    ordername=models.CharField(max_length=100,null=True,blank=True)
    uploaded_on=models.DateTimeField(default=now)
    class Meta:
        db_table='user_file_uploads'
        verbose_name_plural='user_file_uploads'

    def __str__(self)->str:
        return f'{self.user.username} file uploads'

    def delete(self, using=None,keep_parents=False):
        if self.media:
            self.media.storage.delete(self.media.name)
        super().delete()


#customer quote
class CustomerFields(models.Model):
    quote_contact=models.CharField(max_length=200,null=True,blank=True)
    quote_phone=PhoneNumberField(null=True,blank=True,verbose_name='phone',max_length=13)
    quote_email=models.CharField(max_length=100,null=True,blank=True)
    quote_wechat=models.CharField(max_length=200,null=True,blank=True)
    pickup_select=models.CharField(max_length=100,null=True,blank=True)
    pickup_address=models.CharField(max_length=100,null=True,blank=True)
    zipcode=models.CharField(max_length=100,null=True,blank=True)
    internal_order_number=models.CharField(max_length=200,null=True,blank=True)
    pickup_contact_phone=PhoneNumberField(null=True,blank=True,verbose_name='phone',max_length=13)
    pickup_contact=models.CharField(max_length=100,null=True,blank=True)
    pickup_contact_email=models.CharField(max_length=100,null=True,blank=True)
    shipping_select=models.CharField(max_length=100,null=True,blank=True)
    shipping_address=models.CharField(max_length=100,null=True,blank=True)
    shipping_zipcode=models.CharField(max_length=100,null=True,blank=True)
    shipping_order_number=models.CharField(max_length=100,null=True,blank=True)
    shipping_contact=models.CharField(max_length=100,null=True,blank=True)
    shipping_contact_phone=PhoneNumberField(null=True,blank=True,verbose_name='phone',max_length=13)
    shipping_contact_email=models.CharField(max_length=100,null=True,blank=True)
    item_name=models.CharField(max_length=100,null=True,blank=True)
    prefix=models.CharField(max_length=100,null=True,blank=True)
    packaging_board=models.CharField(max_length=100,null=True,blank=True)
    dimensions=models.CharField(max_length=100,null=True,blank=True)
    weight=models.CharField(max_length=100,null=True,blank=True)
    payer=models.CharField(max_length=100,null=True,blank=True)
    media=models.FileField(upload_to='customer/',null=True,blank=True)
    modified_at=models.DateTimeField(default=now)
    created_at=models.DateTimeField(default=now)
    class Meta:
        db_table='customerfields'
        verbose_name_plural='customerfields'
        ordering=('created_at',)
    def __str__(self)->str:
        return self.quote_contact

    def delete(self, using=None,keep_parents=False):
        if self.media:
            self.media.storage.delete(self.media.name)
        super().delete()

    @property
    def get_pref(self):
        return 'QA'+str(self.id).zfill(5)

