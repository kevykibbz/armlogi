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
        model=Oders
        fields=['ordername']
        

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
    pierpass=forms.CharField(widget=forms.DateInput(attrs={'class':'form-control','placeholder':'Pierpass'}),required=False)
    mbl=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'MBL'}),required=False)
    hbl=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'HBL'}),required=False)
    customer=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Customer','list':'customerlist'}),required=False)
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
    driver=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Driver'}),required=False)
    empty_return=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Empty Return'}),required=False)
    chasis=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Chassis'}),required=False)
    demurrage=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Demurrage'}),required=False)
    invoice_sent=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Invoice Sent'}),required=False)
    invoice=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Invoice'}),required=False)
    invoice_dolla=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Invoice $'}),required=False)
    a_rrry=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'A/R'}),required=False)
    a_ppy=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'A/P'}),required=False)
    customer_email=forms.EmailField(widget=forms.EmailInput(attrs={'class':'form-control','placeholder':'Customer Email'}),required=False)
    notify=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Notify'}),required=False)
    acct_email=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'ACCT Email','required':False}),required=False)
    comment=forms.CharField(widget=forms.Textarea(attrs={'rows':5,'cols':20,'class':'form-control','placeholder':'Comment...','required':False}),required=False)
    media=forms.FileField(widget=forms.FileInput(attrs={'class':'custom-file-input','id':'customFileInput'}),required=False)
    class Meta:
        model=OrderFields
        fields=[
                'media',
                'status',
                'date',
                'pierpass',
                'hbl',
                'mbl',
                'customer',
                'container',
                'type',
                'seal',
                'drop_city',
                'discharge_port',
                'port_eta',
                'lfd',
                'trucking',
                'east_deliver','appointment','actual_deliver','driver','empty_return','chasis','demurrage','invoice_sent','invoice','invoice_dolla',
                'a_rrry','a_ppy','customer_email','notify','acct_email','comment',
            ]

#UserFileUploads
class FormUploads(forms.ModelForm):
    media=forms.FileField(widget=forms.FileInput(attrs={'class':'file-input','hidden':True}),required=False)
    
    class Meta:
        model=OrderFields
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
        model=OrderFields
        fields=['customer_email']

    def clean_email(self):
        email=self.cleaned_data['email']
        if  not OrderFields.objects.filter(customer_email=email).exists():
            raise forms.ValidationError('Email address does not exist')
        try:
            validate_email(email)
        except ValidationError:
            raise forms.ValidationError('Invalid email address')
        return email
