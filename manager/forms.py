from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from .models import *
from django import forms
from django.contrib.auth.forms import PasswordResetForm, UserCreationForm,UserChangeForm,PasswordChangeForm
from django.contrib.auth.forms import User
from phonenumber_field.formfields import PhoneNumberField
from phonenumber_field.widgets import PhoneNumberPrefixWidget
from django.contrib.auth.hashers import check_password
from django.core.validators import FileExtensionValidator,URLValidator


class UserResetPassword(PasswordResetForm):
    email=forms.EmailField(widget=forms.EmailInput(attrs={'class':'form-control','placeholder':'Enter email address'}),error_messages={'required':'Email address is required'})

    def clean_email(self):
        email=self.cleaned_data['email']
        if  not User.objects.filter(email=email).exists():
            raise forms.ValidationError('Email address does not exist')
        try:
            validate_email(email)
        except ValidationError:
            raise forms.ValidationError('Invalid email address')
        return email

class users_registerForm(UserCreationForm):
    first_name=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'First name','aria-label':'first_name'}),error_messages={'required':'First name is required'})
    last_name=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Last name','aria-label':'last_name'}),error_messages={'required':'Last name is required'})
    email=forms.EmailField(widget=forms.EmailInput(attrs={'class':'form-control','placeholder':'Email address','aria-label':'email'}),error_messages={'required':'Email address is required'})
    username=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Username ','aria-label':'username'}),error_messages={'required':'Username is required'})
    password1=forms.CharField(widget=forms.PasswordInput(attrs={'class':'form-control','placeholder':'Password Eg Example12','aria-label':'password1'}),error_messages={'required':'Password is required','min_length':'enter atleast 6 characters long'})
    password2=forms.CharField(widget=forms.PasswordInput(attrs={'class':'form-control','placeholder':'Confirm password','aria-label':'password2'}),error_messages={'required':'Confirm password is required'})

    class Meta:
        model=User
        fields=['first_name','last_name','email','username','password1','password2']


    def clean_first_name(self):
        first_name=self.cleaned_data['first_name']
        if not str(first_name).isalpha():
                raise forms.ValidationError('only characters are allowed')
        return first_name
    
    def clean_last_name(self):
        last_name=self.cleaned_data['last_name']
        if not str(last_name).isalpha():
                raise forms.ValidationError('only characters are allowed')
        return last_name
           

    def clean_email(self):
        email=self.cleaned_data['email']
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError('A user with this email already exists')
        try:
            validate_email(email)
        except ValidationError as e:
            raise forms.ValidationError('invalid email address')
        return email
    
    def clean_username(self):
        username=self.cleaned_data['username']
        if User.objects.filter(username=username).exists():
            raise forms.ValidationError('A user with this username already exists')
        return username
options=[
            ('Tertiary','View only'),
            ('Secondary','View | Edit'),
            ('Admin','View | Edit  | Admin'),
        ]
class EProfileForm(forms.ModelForm):
    phone=PhoneNumberField(widget=PhoneNumberPrefixWidget(attrs={'class':'form-control','type':'tel','aria-label':'phone','placeholder':'Phone'}),error_messages={'required':'Phone number is required'})
    role=forms.ChoiceField(required=False,choices=options,initial="Tertiary",widget=forms.Select(attrs={'class':'form-control show-tick ms select2','placeholder':'Role'}))
    profile_pic=forms.ImageField(
                                widget=forms.FileInput(attrs={'class':'profile','accept':'image/*','hidden':True}),
                                required=False,
                                validators=[FileExtensionValidator(['jpg','jpeg','png','gif'],message="Invalid image extension",code="invalid_extension")]
                                )
    class Meta:
        model=ExtendedAuthUser
        fields=['phone','role','profile_pic']

    
    def clean_phone(self):
        phone=self.cleaned_data['phone']
        if phone !='':
            if ExtendedAuthUser.objects.filter(phone=phone).exists():
                raise forms.ValidationError('A user with this phone number already exists.')
            else:
                return phone
        else:
            raise forms.ValidationError('Phone number is required')

#profileForm
class UserProfileChangeForm(UserChangeForm):
    first_name=forms.CharField(widget=forms.TextInput(attrs={'style':'text-transform:lowercase;','class':'form-control'}),required=False)
    last_name=forms.CharField(widget=forms.TextInput(attrs={'style':'text-transform:lowercase;','class':'form-control','aria-label':'last_name'}),error_messages={'required':'Last name is required'})
    email=forms.EmailField(widget=forms.EmailInput(attrs={'style':'text-transform:lowercase;','class':'form-control','aria-label':'email'}),error_messages={'required':'Email address is required'})
    class Meta:
        model=User
        fields=['first_name','last_name','email']


    def clean_first_name(self):
        first_name=self.cleaned_data['first_name']
        if not str(first_name).isalpha():
                raise forms.ValidationError('only characters are allowed.')
        return first_name
    
    def clean_last_name(self):
        last_name=self.cleaned_data['last_name']
        if not str(last_name).isalpha():
                raise forms.ValidationError('only characters are allowed.')
        return last_name

    def clean_email(self):
        email=self.cleaned_data['email']
        if email != self.instance.email:
            if User.objects.filter(email=email).exists():
                raise forms.ValidationError('A user with this email already exists.')
            try:
                validate_email(email)
            except ValidationError as e:
                raise forms.ValidationError('Invalid email address.')
            return email
        else:
           return email

options=[
        ('Tertiary','View only'),
        ('Secondary','View | Edit'),
        ('Admin','View | Edit  | Admin'),
        ]
#profileForm
class ExtendedUserProfileChangeForm(forms.ModelForm):
    phone=PhoneNumberField(widget=PhoneNumberPrefixWidget(attrs={'class':'form-control','type':'tel','aria-label':'phone','placeholder':'Phone'}),error_messages={'required':'Phone number is required'})
    role=forms.ChoiceField(choices=options,initial="Tertiary",required=False,widget=forms.Select(attrs={'class':'form-control show-tick ms select2','placeholder':'Role'}))
    profile_pic=forms.ImageField(
                                widget=forms.FileInput(attrs={'class':'profile','accept':'image/*','hidden':True}),
                                required=False,
                                validators=[FileExtensionValidator(['jpg','jpeg','png','gif'],message="Invalid image extension",code="invalid_extension")]
                                )
    class Meta:
        model=ExtendedAuthUser
        fields=['phone','role','profile_pic']

    
    def clean_phone(self):
        phone=self.cleaned_data['phone']
        if phone != self.instance.phone:
            if ExtendedAuthUser.objects.filter(phone=phone).exists():
                raise forms.ValidationError('A user with this phone number already exists.')
            else:
                return phone
        else:
           return phone 


#profileForm
class CurrentUserProfileChangeForm(UserChangeForm):
    first_name=forms.CharField(widget=forms.TextInput(attrs={'style':'text-transform:lowercase;','class':'form-control'}),required=False)
    last_name=forms.CharField(widget=forms.TextInput(attrs={'style':'text-transform:lowercase;','class':'form-control','aria-label':'last_name'}),error_messages={'required':'Last name is required'})
    email=forms.EmailField(widget=forms.EmailInput(attrs={'style':'text-transform:lowercase;','class':'form-control','aria-label':'email'}),error_messages={'required':'Email address is required'})
    class Meta:
        model=User
        fields=['first_name','last_name','email']


    def clean_first_name(self):
        first_name=self.cleaned_data['first_name']
        if not str(first_name).isalpha():
                raise forms.ValidationError('only characters are allowed.')
        return first_name
    
    def clean_last_name(self):
        last_name=self.cleaned_data['last_name']
        if not str(last_name).isalpha():
                raise forms.ValidationError('only characters are allowed.')
        return last_name

    def clean_email(self):
        email=self.cleaned_data['email']
        if email != self.instance.email:
            if User.objects.filter(email=email).exists():
                raise forms.ValidationError('A user with this email already exists.')
            try:
                validate_email(email)
            except ValidationError as e:
                raise forms.ValidationError('Invalid email address.')
            return email
        else:
           return email

user_roles=[
        ('Tertiary','View only'),
        ('Secondary','View | Edit'),
        ('Admin','View | Edit | Admin'),
    ]
#profileForm
class CurrentExtendedUserProfileChangeForm(forms.ModelForm):
    phone=PhoneNumberField(widget=PhoneNumberPrefixWidget(attrs={'class':'form-control','type':'tel','aria-label':'phone','placeholder':'Phone example +25479626...'}),error_messages={'required':'Phone number is required'})
    role=forms.ChoiceField(choices=user_roles,initial="Tertiary", error_messages={'required':'Role is required','aria-label':'role'},widget=forms.Select(attrs={'class':'form-control show-tick ms select2','placeholder':'Role'}))
    profile_pic=forms.ImageField(
                                widget=forms.FileInput(attrs={'class':'profile','accept':'image/*','hidden':True}),
                                required=False,
                                validators=[FileExtensionValidator(['jpg','jpeg','png','gif'],message="Invalid image extension",code="invalid_extension")]
                                )
    class Meta:
        model=ExtendedAuthUser
        fields=['phone','profile_pic']

    
    def clean_phone(self):
        phone=self.cleaned_data['phone']
        if phone != self.instance.phone:
            if ExtendedAuthUser.objects.filter(phone=phone).exists():
                raise forms.ValidationError('A user with this phone number already exists.')
            else:
                return phone
        else:
           return phone 

class UserPasswordChangeForm(UserCreationForm):
    oldpassword=forms.CharField(widget=forms.PasswordInput(attrs={'class':'form-control','placeholder':'Old password','aria-label':'oldpassword'}),error_messages={'required':'Old password is required','min_length':'enter atleast 6 characters long'})
    password1=forms.CharField(widget=forms.PasswordInput(attrs={'class':'form-control','placeholder':'New password Eg Example12','aria-label':'password1'}),error_messages={'required':'New password is required','min_length':'enter atleast 6 characters long'})
    password2=forms.CharField(widget=forms.PasswordInput(attrs={'class':'form-control','placeholder':'Confirm new password','aria-label':'password2'}),error_messages={'required':'Confirm new password is required'})

    class Meta:
        model=User
        fields=['password1','password2']
    
    def clean_oldpassword(self):
        oldpassword=self.cleaned_data['oldpassword']
        if not self.instance.check_password(oldpassword):
            raise forms.ValidationError('Wrong old password.')
        else:
           return oldpassword 

class NewOderForm(forms.ModelForm):
    ordername=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Order name','aria-label':'neworder','list':'orderlist'}),error_messages={'required':'Order name is required'})
    class Meta:
        model=OrderModel
        fields=['ordername',]
        

options=[
            ("",""),
            ("Cancelled pickup","Cancelled pickup"),
            ("On ship","On ship"),
            ("Invoice sent","Invoice sent"),
            ("closed area","Closed area"),
            ("Assigned driver","Assigned driver"),
            ("Delivered","Delivered"),
            ("Do recd","Do Recd"),
        ]
class OrderFieldsForm(forms.ModelForm):
    status=forms.ChoiceField(choices=options,widget=forms.Select(attrs={'class':'form-control show-tick ms select2','data-placeholder':'Select'}),required=False)
    date=forms.DateField(widget=forms.DateInput(attrs={'class':'form-control','placeholder':'Date','type':'Date'}),required=False)
    pierpass=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Pierpass'}),required=False)
    pierpass_dolla=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Pierpass $'}),required=False)
    exam=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Exam'}),required=False)
    mbl=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'MBL'}),required=False)
    hbl=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'HBL'}),required=False)
    customer=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Customer','list':'customerlist'}),required=False)
    ship_to=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Ship To'}),required=False)
    container=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Container#'}),required=False)
    type=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Type'}),required=False)
    seal=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Seal#'}),required=False)
    drop_city=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Drop City'}),required=False)
    discharge_port=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Discharge port'}),required=False)
    port_eta=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Port ETA'}),required=False)
    lfd=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'LFD'}),required=False)
    trucking=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Trucking'}),required=False)
    east_deliver=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Est.Deliver'}),required=False)
    appointment=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Appoitment'}),required=False)
    actual_deliver=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Actual Deliver'}),required=False)
    full_out_driver=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Full-Out Driver'}),required=False)
    empty_return=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Empty Return'}),required=False)
    empty_in_driver=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Empty-In Driver'}),required=False)
    chasis=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Chassis'}),required=False)
    demurrage=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Demurrage'}),required=False)
    demurrage_dolla=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Demurrage $'}),required=False)
    do_recd=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'DO RECD Date'}),required=False)
    invoice_sent=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Invoice Sent'}),required=False)
    invoice=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Invoice'}),required=False)
    invoice_dolla=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Invoice $'}),required=False)
    per_diem=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'PER DIEM'}),required=False)
    sml=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'SML'}),required=False)
    a_rrry=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'A/R'}),required=False)
    a_ppy=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'A/P'}),required=False)
    customer_email=forms.EmailField(widget=forms.EmailInput(attrs={'class':'form-control','placeholder':'Customer Email'}),required=False)
    notify=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Notify'}),required=False)
    acct_email=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'ACCT Email','required':False}),required=False)
    comment=forms.CharField(widget=forms.Textarea(attrs={'rows':5,'cols':20,'class':'form-control','placeholder':'Comment...','required':False}),required=False)
    media=forms.FileField(widget=forms.FileInput(attrs={'class':'custom-file-input','id':'customFileInput'}),required=False)
    class Meta:
        model=OrderModel
        fields=[
                'media',
                'status',
                'date',
                'pierpass','pierpass_dolla','exam',
                'hbl',
                'mbl',
                'customer','ship_to',
                'container',
                'type',
                'seal',
                'drop_city',
                'discharge_port',
                'port_eta',
                'lfd',
                'trucking',
                'east_deliver','appointment','actual_deliver','full_out_driver','empty_in_driver','empty_return','chasis','demurrage','demurrage_dolla','do_recd','invoice_sent','invoice','invoice_dolla','per_diem','sml',
                'a_rrry','a_ppy','customer_email','notify','acct_email','comment',
            ]
#OrderLogs
class OrderFieldsFormLogs(forms.ModelForm):
    status=forms.ChoiceField(choices=options,widget=forms.Select(attrs={'class':'form-control show-tick ms select2','data-placeholder':'Select'}),required=False)
    date=forms.DateField(widget=forms.DateInput(attrs={'class':'form-control','placeholder':'Date','type':'Date'}),required=False)
    pierpass=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Pierpass'}),required=False)
    pierpass_dolla=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Pierpass $'}),required=False)
    exam=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Exam'}),required=False)
    mbl=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'MBL'}),required=False)
    hbl=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'HBL'}),required=False)
    customer=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Customer','list':'customerlist'}),required=False)
    ship_to=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Ship To'}),required=False)
    container=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Container#'}),required=False)
    type=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Type'}),required=False)
    seal=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Seal#'}),required=False)
    drop_city=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Drop City'}),required=False)
    discharge_port=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Discharge port'}),required=False)
    port_eta=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Port ETA'}),required=False)
    lfd=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'LFD'}),required=False)
    trucking=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Trucking'}),required=False)
    east_deliver=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Est.Deliver'}),required=False)
    appointment=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Appoitment'}),required=False)
    actual_deliver=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Actual Deliver'}),required=False)
    full_out_driver=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Full-Out Driver'}),required=False)
    empty_return=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Empty Return'}),required=False)
    empty_in_driver=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Empty-In Driver'}),required=False)
    chasis=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Chassis'}),required=False)
    demurrage=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Demurrage'}),required=False)
    demurrage_dolla=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Demurrage $'}),required=False)
    do_recd=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'DO RECD Date'}),required=False)
    invoice_sent=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Invoice Sent'}),required=False)
    invoice=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Invoice'}),required=False)
    invoice_dolla=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Invoice $'}),required=False)
    per_diem=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'PER DIEM'}),required=False)
    sml=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'SML'}),required=False)
    a_rrry=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'A/R'}),required=False)
    a_ppy=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'A/P'}),required=False)
    customer_email=forms.EmailField(widget=forms.EmailInput(attrs={'class':'form-control','placeholder':'Customer Email'}),required=False)
    notify=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Notify'}),required=False)
    acct_email=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'ACCT Email','required':False}),required=False)
    comment=forms.CharField(widget=forms.Textarea(attrs={'rows':5,'cols':20,'class':'form-control','placeholder':'Comment...','required':False}),required=False)
    media=forms.FileField(widget=forms.FileInput(attrs={'class':'custom-file-input','id':'customFileInput'}),required=False)
    class Meta:
        model=OrderLogData
        fields=[
                'media',
                'status',
                'date',
                'pierpass','pierpass_dolla','exam',
                'hbl',
                'mbl',
                'customer','ship_to',
                'container',
                'type',
                'seal',
                'drop_city',
                'discharge_port',
                'port_eta',
                'lfd',
                'trucking',
                'east_deliver','appointment','actual_deliver','full_out_driver','empty_in_driver','empty_return','chasis','demurrage','demurrage_dolla','do_recd','invoice_sent','invoice','invoice_dolla','per_diem','sml',
                'a_rrry','a_ppy','customer_email','notify','acct_email','comment',
            ]
    def clean_status(self):
        status=self.cleaned_data.get('status')
        if self.instance.status != status:
            if status is not None and len(status) > 0:
                return status
            else:
                return 'Erased'
        
    def clean_pierpass(self):
        pierpass=self.cleaned_data.get('pierpass')
        if self.instance.pierpass != pierpass:
            if pierpass is not None and len(pierpass) > 0:
                return pierpass
            else:
                return 'Erased'

    def clean_pierpass_dolla(self):
        pierpass_dolla=self.cleaned_data.get('pierpass_dolla')
        if self.instance.pierpass_dolla != pierpass_dolla:
            if pierpass_dolla is not None and len(pierpass_dolla) > 0:
                return pierpass_dolla
            else:
                return 'Erased'

    def clean_exam(self):
        exam=self.cleaned_data.get('exam')
        if self.instance.exam != exam:
            if exam is not None and len(exam) > 0:
                return exam
            else:
                return 'Erased'
        
    def clean_mbl(self):
        mbl=self.cleaned_data.get('mbl')
        if self.instance.mbl != mbl:
            if mbl is not None and len(mbl) > 0:
                return mbl
            else:
                return 'Erased'

    def clean_hbl(self):
        hbl=self.cleaned_data.get('hbl')
        if self.instance.hbl != hbl:
            if hbl is not None and len(hbl) > 0:
                return hbl
            else:
                return 'Erased'

    def clean_customer(self):
        customer=self.cleaned_data.get('customer')
        if self.instance.customer != customer:
            if customer is not None and len(customer) > 0:
                return customer
            else:
                return 'Erased'

    def clean_ship_to(self):
        ship_to=self.cleaned_data.get('ship_to')
        if self.instance.ship_to != ship_to:
            if ship_to is not None and len(ship_to) > 0:
                return ship_to
            else:
                return 'Erased'

    def clean_container(self):
        container=self.cleaned_data.get('container')
        if self.instance.container != container:
            if container is not None and len(container) > 0:
                return container
            else:
                return 'Erased'

    def clean_type(self):
        type=self.cleaned_data.get('type')
        if self.instance.type != type:
            if type is not None and len(type) > 0:
                return type
            else:
                return 'Erased'

    def clean_seal(self):
        seal=self.cleaned_data.get('seal')
        if self.instance.seal != seal:
            if seal is not None and len(seal) > 0:
                return seal
            else:
                return 'Erased'

    def clean_drop_city(self):
        drop_city=self.cleaned_data.get('drop_city')
        if self.instance.drop_city != drop_city:
            if drop_city is not None and len(drop_city) > 0:
                return drop_city
            else:
                return 'Erased'

    def clean_discharge_port(self):
        discharge_port=self.cleaned_data.get('discharge_port')
        if self.instance.discharge_port != discharge_port:
            if discharge_port is not None and len(discharge_port) > 0:
                return discharge_port
            else:
                return 'Erased'

    def clean_port_eta(self):
        port_eta=self.cleaned_data.get('port_eta')
        if self.instance.port_eta != port_eta:
            if port_eta is not None and len(port_eta) > 0:
                return port_eta
            else:
                return 'Erased'

    def clean_lfd(self):
        lfd=self.cleaned_data.get('lfd')
        if self.instance.lfd != lfd:
            if lfd is not None and len(lfd) > 0:
                return lfd
            else:
                return 'Erased'

    def clean_trucking(self):
        trucking=self.cleaned_data.get('trucking')
        if self.instance.trucking != trucking:
            if trucking is not None and len(trucking) > 0:
                return trucking
            else:
                return 'Erased'

    def clean_east_deliver(self):
        east_deliver=self.cleaned_data.get('east_deliver')
        if self.instance.east_deliver != east_deliver:
            if east_deliver is not None and len(east_deliver) > 0:
                return east_deliver
            else:
                return 'Erased'

    def clean_appointment(self):
        appointment=self.cleaned_data.get('appointment')
        if self.instance.appointment != appointment:
            if appointment is not None and len(appointment) > 0:
                return appointment
            else:
                return 'Erased'

    def clean_full_out_driver(self):
        full_out_driver=self.cleaned_data.get('full_out_driver')
        if self.instance.driver != full_out_driver:
            if full_out_driver is not None and len(full_out_driver) > 0:
                return full_out_driver
            else:
                return 'Erased'

    def clean_actual_deliver(self):
        actual_deliver=self.cleaned_data.get('actual_deliver')
        if self.instance.actual_deliver != actual_deliver:
            if actual_deliver is not None and len(actual_deliver) > 0:
                return actual_deliver
            else:
                return 'Erased'

    def clean_empty_return(self):
        empty_return=self.cleaned_data.get('empty_return')
        if self.instance.empty_return != empty_return:
            if empty_return is not None and len(empty_return) > 0:
                return empty_return
            else:
                return 'Erased'
    
    def clean_empty_in_driver(self):
        empty_in_driver=self.cleaned_data.get('empty_in_driver')
        if self.instance.pierpass != empty_in_driver:
            if empty_in_driver is not None and len(empty_in_driver) > 0:
                return empty_in_driver
            else:
                return 'Erased'

    def clean_chasis(self):
        chasis=self.cleaned_data.get('chasis')
        if self.instance.port_eta != chasis:
            if chasis is not None and len(chasis) > 0:
                return chasis
            else:
                return 'Erased'

    def clean_demurrage(self):
        demurrage=self.cleaned_data.get('demurrage')
        if self.instance.demurrage != demurrage:
            if demurrage is not None and len(demurrage) > 0:
                return demurrage
            else:
                return 'Erased'

    def clean_demurrage_dolla(self):
        demurrage_dolla=self.cleaned_data.get('demurrage_dolla')
        if self.instance.demurrage != demurrage_dolla:
            if demurrage_dolla is not None and len(demurrage_dolla) > 0:
                return demurrage_dolla
            else:
                return 'Erased'
    
    def clean_do_recd(self):
        do_recd=self.cleaned_data.get('do_recd')
        if self.instance.do_recd != do_recd:
            if do_recd is not None and len(do_recd) > 0:
                return do_recd
            else:
                return 'Erased'

    def clean_invoice_sent(self):
        invoice_sent=self.cleaned_data.get('invoice_sent')
        if self.instance.invoice_sent != invoice_sent:
            if invoice_sent is not None and len(invoice_sent) > 0:
                return invoice_sent
            else:
                return 'Erased'

    def clean_invoice(self):
        invoice=self.cleaned_data.get('invoice')
        if self.instance.invoice != invoice:
            if invoice is not None and len(invoice) > 0:
                return invoice
            else:
                return 'Erased'

    def clean_invoice_dolla(self):
        invoice_dolla=self.cleaned_data.get('invoice_dolla')
        if self.instance.invoice_dolla != invoice_dolla:
            if invoice_dolla is not None and len(invoice_dolla) > 0:
                return invoice_dolla
            else:
                return 'Erased'

    def clean_per_diem(self):
        per_diem=self.cleaned_data.get('per_diem')
        if self.instance.per_diem != per_diem:
            if per_diem is not None and len(per_diem) > 0:
                return per_diem
            else:
                return 'Erased'
    
    def clean_sml(self):
        sml=self.cleaned_data.get('sml')
        if self.instance.sml != sml:
            if sml is not None and len(sml) > 0:
                return sml
            else:
                return 'Erased'
    
    def clean_a_rrry(self):
        a_rrry=self.cleaned_data.get('a_rrry')
        if self.instance.a_rrry != a_rrry:
            if a_rrry is not None and len(a_rrry) > 0:
                return a_rrry
            else:
                return 'Erased'

    def clean_a_ppy(self):
        a_ppy=self.cleaned_data.get('a_ppy')
        if self.instance.a_ppy != a_ppy:
            if a_ppy is not None and len(a_ppy) > 0:
                return a_ppy
            else:
                return 'Erased'

    def clean_customer_email(self):
        customer_email=self.cleaned_data.get('customer_email')
        if self.instance.customer_email != customer_email:
            if customer_email is not None and len(customer_email) > 0:
                return customer_email
            else:
                return 'Erased'
    
    def clean_notify(self):
        notify=self.cleaned_data.get('notify')
        if self.instance.notify != notify:
            if notify is not None and len(notify) > 0:
                return notify
            else:
                return 'Erased'

    def clean_acct_email(self):
        acct_email=self.cleaned_data.get('acct_email')
        if self.instance.acct_email != acct_email:
            if acct_email is not None and len(acct_email) > 0:
                return acct_email
            else:
                return 'Erased'

    def clean_date(self):
        date=self.cleaned_data.get('date')
        if self.instance.date != date:
            if date is not None and len(date) > 0:
                return date
            else:
                return None

    def clean_media(self):
        media=self.cleaned_data.get('media')
        if self.instance.media != media:
           return media
       
       
    def clean_comment(self):
        comment=self.cleaned_data.get('comment')
        if self.instance.comment != comment:
            if comment is not None and len(comment) > 0:
                return comment
            else:
                return 'Erased'


#UserFileUploads
class FormUploads(forms.ModelForm):
    media=forms.FileField(widget=forms.FileInput(attrs={'class':'file-input','hidden':True}),required=False)
    
    class Meta:
        model=OrderModel
        fields=['media']

#CustomerFileUploads
class CustomerUploads(forms.ModelForm):
    media=forms.FileField(widget=forms.FileInput(attrs={'class':'file-input','hidden':True}),required=False)
    
    class Meta:
        model=CustomerFields
        fields=['media']

opt=[
            ("Business","Business"),
            ("Residential","Residential"),
        ]
#CustomerForm
class CustomerForm(forms.ModelForm):
    quote_contact=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Quote Contact','aria-label':'quote_contact'}),error_messages={'required':'Quote contact is required'})
    quote_phone=PhoneNumberField(widget=PhoneNumberPrefixWidget(attrs={'class':'form-control phonefield','type':'tel','aria-label':'quote_phone'}),error_messages={'required':'Applicant quote phone is required'})
    quote_email=forms.EmailField(widget=forms.EmailInput(attrs={'class':'form-control','placeholder':'Applicant Quote Email Address','aria-label':'quote_email'}),error_messages={'required':'Applicant quote email address is required'})
    quote_wechat=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Applicant Quote WeChat','aria-label':'quote_wechat'}),required=False)
    pickup_select=forms.ChoiceField(choices=opt,widget=forms.RadioSelect(attrs={'class':'form-check-input','type':'radio','aria-label':'pickup_select'}),error_messages={'required':'Pickup category is required'})
    pickup_address=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Pickup Address','aria-label':'pickup_address'}),error_messages={'required':'Pickup address is required'})
    zipcode=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'ZipCode','aria-label':'zipcode'}),error_messages={'required':'Zipcode is required'})
    internal_order_number=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Pickup Internal Order Number','aria-label':'internal_order_number'}),error_messages={'required':'Pickup internal order number is required'})
    pickup_contact=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Pickup Contact','aria-label':'pickup_contact'}),error_messages={'required':'Pickup contact'})
    pickup_contact_phone=PhoneNumberField(widget=PhoneNumberPrefixWidget(attrs={'class':'form-control phonefield','type':'tel','aria-label':'pickup_contact_phone','placeholder':'Pickup Contact Phone'}),error_messages={'required':'Pickup contact phone is required'})
    pickup_contact_email=forms.EmailField(widget=forms.EmailInput(attrs={'class':'form-control','placeholder':'Pickup Email Address','aria-label':'pickup_contact_email'}),error_messages={'required':'Pickup email address is required'})
    shipping_select=forms.ChoiceField(choices=opt,widget=forms.RadioSelect(attrs={'class':'form-check-input','type':'radio','aria-label':'shipping_select'}))
    shipping_address=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Shipping Address','aria-label':'shipping_address'}),error_messages={'required':'Shipping address is required'})
    shipping_zipcode=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Shipping Zipcode','aria-label':'shipping_zipcode'}),error_messages={'required':'Shipping zipcode is required'})
    shipping_order_number=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Shipping Address Order Number','aria-label':'shipping_order_number'}),error_messages={'required':'Shipping order number is required'})
    shipping_contact=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Shipping Contact','aria-label':'shipping_contact'}),error_messages={'required':'Shipping contact is required'})
    shipping_contact_phone=PhoneNumberField(widget=PhoneNumberPrefixWidget(attrs={'class':'form-control phonefield','type':'tel','aria-label':'shipping_contact_phone','placeholder':'Shipping Contact Phone'}),error_messages={'required':'Shipping contact phone is required'})
    shipping_contact_email=forms.EmailField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Shipping Contact Email Address','aria-label':'shipping_contact_email'}),error_messages={'required':'Shipping contact email is required'})
    item_name=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Item Name or Category','aria-label':'item_name'}),error_messages={'required':'Item name is required'})
    packaging_board=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Packaging Board/Carton/Wooden Crate/Pallet/Box/Crate','aria-label':'packaging_board'}),error_messages={'required':'Packaging board/carton/wooden crate/pallet/box/crate is required'})
    dimensions=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Length,Width,Height','aria-label':'dimensions'}),error_messages={'required':'Dimensions is required'})
    weight=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Weight:pounds (LB)','aria-label':'weight'}),error_messages={'required':'Weight is required'})
    payer=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Payer or Paying Company Billed To','aria-label':'payer'}),error_messages={'required':'Payer or paying company billed to is required'})
    media=forms.FileField(widget=forms.FileInput(attrs={'class':'custom-file-input','id':'customFileInput'}),required=False)

    class Meta:
        model=CustomerFields
        fields=[
                'quote_contact',
                'quote_phone',
                'quote_email',
                'quote_wechat',
                'pickup_select',
                'pickup_address',
                'zipcode',
                'internal_order_number',
                'pickup_contact',
                'pickup_contact_phone',
                'pickup_contact_email',
                'shipping_select',
                'shipping_address',
                'shipping_zipcode',
                'shipping_order_number',
                'shipping_contact','shipping_contact_phone','shipping_contact_email','item_name','packaging_board','dimensions','weight','payer','media',
            ]


#AuthForm
class AuthForm(forms.ModelForm):
    email=forms.EmailField(widget=forms.EmailInput(attrs={'style':'text-transform:lowercase;','class':'form-control','aria-label':'email'}),error_messages={'required':'Email address is required'})
    class Meta:
        model=OrderModel
        fields=['customer_email']

    def clean_email(self):
        email=self.cleaned_data['email']
        if  not OrderModel.objects.filter(customer_email=email).exists():
            raise forms.ValidationError('Email address does not exist')
        try:
            validate_email(email)
        except ValidationError:
            raise forms.ValidationError('Invalid email address')
        return email

class DoIncomingsForm(forms.ModelForm):
    #pdf=forms.FileField(widget=forms.FileInput(attrs={'aria-label':'pdf','class':'custom-file-input','id':'customFileInput'}),required=False)
    pdf=forms.FileField(widget=forms.FileInput(attrs={'aria-label':'pdf','class':'custom-file-input','id':'customFileInput'}),error_messages={'required':'Excel or PDF file is required'},validators=[FileExtensionValidator(['pdf','xlsx',],message="Invalid file extension.Allowed file extensions are .pdf,.xlsx",code="invalid_extension")])
    cntr=forms.CharField(widget=forms.DateInput(attrs={'aria-label':'cntr','class':'form-control','placeholder':'CNTR#'}),error_messages={'required':'CNTR is required'})
    mbl=forms.CharField(widget=forms.TextInput(attrs={'aria-label':'mbl','class':'form-control','placeholder':'MBL'}),error_messages={'required':'MBL is required'})
    seal=forms.CharField(widget=forms.TextInput(attrs={'aria-label':'seal','class':'form-control','placeholder':'Seal#'}),error_messages={'required':'Seal is required'})
    ship=forms.CharField(widget=forms.TextInput(attrs={'aria-label':'ship','class':'form-control','placeholder':'Ship'}),error_messages={'required':'Ship is required'})
    size=forms.CharField(widget=forms.TextInput(attrs={'aria-label':'size','class':'form-control','placeholder':'Size'}),error_messages={'required':'Size is required'})
    weight=forms.CharField(widget=forms.TextInput(attrs={'aria-label':'weight','class':'form-control','placeholder':'Weight'}),error_messages={'required':'Weight is required'})
    type=forms.CharField(widget=forms.TextInput(attrs={'aria-label':'type','class':'form-control','placeholder':'Type'}),error_messages={'required':'Type is required'})
    port=forms.CharField(widget=forms.TextInput(attrs={'aria-label':'port','class':'form-control','placeholder':'Port'}),error_messages={'required':'Port is required'})
    eta=forms.CharField(widget=forms.TextInput(attrs={'aria-label':'eta','class':'form-control','placeholder':'ETA'}),error_messages={'required':'ETA is required'})
    drop_city=forms.CharField(widget=forms.TextInput(attrs={'aria-label':'drop_city','class':'form-control','placeholder':'Drop City'}),error_messages={'required':'Drop City is required'})
    class Meta:
        model=DoIncomingsModel
        fields=['pdf','cntr','mbl','seal','ship','size','weight','type','port','eta','drop_city',]