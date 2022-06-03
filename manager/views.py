from manager.decorators import unauthenticated_user,allowed_users
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from .models import Oders,ExtendedAuthUser,OrderFields,UserFileUploads,CustomerFields,LoggerData
from django.contrib.auth.models import User,Group,Permission
from django.contrib.contenttypes.models import ContentType
from django.shortcuts import render,get_object_or_404
from django.views.generic import View
from django.contrib.auth import authenticate,login,logout
from django.http import JsonResponse,HttpResponse
from installation.models import SiteConstants
from django.shortcuts import redirect
from .forms import *
from django.core.paginator import Paginator
from django.contrib.sites.shortcuts import get_current_site
from .addons import send_email,getSiteData
import json
from django.core.files.storage import FileSystemStorage
from django.contrib.auth.hashers import make_password
from django.contrib.auth import update_session_auth_hash
import re
from .search import *
import datetime
from django.contrib.humanize.templatetags.humanize import intcomma
from django.template.defaulttags import register
import math
from django.utils.crypto import get_random_string
from manager.addons import send_email


#save logger data
def save_logger(action,user,role):
    if action and user:
        y=LoggerData.objects.create(action=action,user=user,role=role)
        y.save()



@method_decorator(unauthenticated_user,name='dispatch')
class Dashboard(View):
    def get(self,request):
        obj=SiteConstants.objects.all()[0]
        data={
            'title':'Login',
            'obj':obj
        }
        return render(request,'manager/login.html',context=data)
    def post(self,request):
        if request.headers.get('x-requested-with') == 'XMLHttpRequest':
            key=request.POST['username']
            password=request.POST['password']
            if key:
                if password:
                    regex=re.compile(r'([A-Za-z0-9+[.-_]])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+')
                    if re.fullmatch(regex,key):
                        #email address
                        if User.objects.filter(email=key).exists():
                            data=User.objects.get(email=key)
                            user=authenticate(username=data.username,password=password)
                        else:
                            form_errors={"username": ["Invalid email address."]}
                            return JsonResponse({'valid':False,'form_errors':form_errors},content_type="application/json")
                    else:
                        #username
                        if User.objects.filter(username=key).exists():
                            user=authenticate(username=key,password=password)
                        else:
                            form_errors={"username": ["Invalid username."]}
                            return JsonResponse({'valid':False,'form_errors':form_errors},content_type="application/json")
                        
                    if user is not None:
                        if 'remember' in request.POST:
                           request.session.set_expiry(1209600) #two weeeks
                        else:
                           request.session.set_expiry(0) 
                        login(request,user)
                        role=request.user.extendedauthuser.role
                        save_logger(f'User with role of :{role} logged into the system.',request.user.get_full_name(),role)
                        return JsonResponse({'valid':True,'feedback':'success:login successfully.'},content_type="application/json")
                    form_errors={"password": ["Password is incorrect or inactive account."]}
                    return JsonResponse({'valid':False,'form_errors':form_errors},content_type="application/json")
                else:
                    form_errors={"password": ["Password is required."]}
                    return JsonResponse({'valid':False,'form_errors':form_errors},content_type="application/json")
            else:
                form_errors={"username": ["Username is required."]}
                return JsonResponse({'valid':False,'form_errors':form_errors},content_type="application/json")


@login_required(login_url='/')
def home(request):
    obj=SiteConstants.objects.all()[0]
    users_count=User.objects.count()
    orders_count=Oders.objects.count()
    completed_orders=OrderFields.objects.filter(status__icontains='delivered').count()
    cancelled_orders=OrderFields.objects.filter(status__icontains='cancelled').count()
    orders=OrderFields.objects.all().order_by('-modified_at')[:12]
    data={
        'title':'home',
        'obj':obj,
        'data':request.user,
        'users_count':users_count,
        'orders_count':orders_count,
        'completed_orders':completed_orders,
        'cancelled_orders':cancelled_orders,
        'orders':orders
    }
    return render(request,'manager/home.html',context=data)

#logout
def user_logout(request):
    role=request.user.extendedauthuser.role
    save_logger(f'User with role of :{role} logged out of the system.',request.user.get_full_name(),role)
    logout(request)
    return redirect('/')



#newUser
@method_decorator(login_required(login_url='/'),name='dispatch')
@method_decorator(allowed_users(allowed_roles=['admins']),name='dispatch')
class newUser(View):
    def get(self,request):
        obj=SiteConstants.objects.all()[0]
        form=users_registerForm()
        eform=EProfileForm()
        data={
            'title':'Add new user',
            'obj':obj,
            'data':request.user,
            'form':form,
            'eform':eform
        }
        return render(request,'manager/new_user.html',context=data)
    def post(self,request,*args,**kwargs):
        if request.method == 'POST' and request.headers.get('x-requested-with') == 'XMLHttpRequest':
                uform=users_registerForm(request.POST or None)
                eform=EProfileForm(request.POST , request.FILES or None)
                if uform.is_valid() and  eform.is_valid():
                    userme=uform.save(commit=False)
                    userme.is_active = True
                    userme.save()
                    extended=eform.save(commit=False)
                    extended.user=userme
                    extended.initials=uform.cleaned_data.get('first_name')[0].upper()+uform.cleaned_data.get('last_name')[0].upper()
                    extended.save()
                    user=User.objects.get(email__exact=uform.cleaned_data.get('email'))
                    ct=ContentType.objects.get_for_model(ExtendedAuthUser)
                    role=eform.cleaned_data.get('role')
                    if 'Secondary' in role:
                        if not Group.objects.filter(name='secondary').exists():
                            group=Group.objects.create(name='secondary')
                            group.user_set.add(userme)
                            p1=Permission.objects.filter(content_type=ct).all()[0]
                            p3=Permission.objects.filter(content_type=ct).all()[2]
                            group.permissions.add(p1)
                            group.permissions.add(p3)
                            group.save()
                        else:
                            group=Group.objects.get(name__icontains='secondary')
                            group.user_set.add(userme)
                            group.save()
                    elif 'Tertiary' in role:
                        if not Group.objects.filter(name='tertiary').exists():
                            group=Group.objects.create(name='tertiary')
                            group.user_set.add(userme)
                            p3=Permission.objects.filter(content_type=ct).all()[2]
                            group.permissions.add(p3)
                            group.save()
                        else:
                            group=Group.objects.get(name__icontains='tertiary')
                            group.user_set.add(userme)
                            group.save()
                    newuser=uform.cleaned_data.get('first_name')+' '+uform.cleaned_data.get('last_name')
                    role=request.user.extendedauthuser.role
                    save_logger(f'created new user:{newuser}',request.user.get_full_name(),role)
                    return JsonResponse({'valid':True,'message':'user added successfully','profile_pic':user.extendedauthuser.profile_pic.url},content_type="application/json")
                else:
                    return JsonResponse({'valid':False,'uform_errors':uform.errors,'eform_errors':eform.errors},content_type="application/json")

#viewUsers
@login_required(login_url='/')
@allowed_users(allowed_roles=['admins'])
def viewUsers(request):
    obj=SiteConstants.objects.all()[0]
    data=User.objects.all().order_by('-id')
    paginator=Paginator(data,10)
    page_num=request.GET.get('page')
    users=paginator.get_page(page_num)
    data={
        'title':'View users',
        'obj':obj,
        'data':request.user,
        'users':users,
        'count':paginator.count,
    }
    return render(request,'manager/view_users.html',context=data)

#edit user
@method_decorator(login_required(login_url='/'),name='dispatch')
@method_decorator(allowed_users(allowed_roles=['admins']),name='dispatch')
class EditUser(View):
    def get(self,request,id):
        obj=SiteConstants.objects.all()[0]
        user=User.objects.get(extendedauthuser__user_id__exact=id)
        form=UserProfileChangeForm(instance=user)
        eform=ExtendedUserProfileChangeForm(instance=user.extendedauthuser)
        data={
            'title':f'Edit user | {user.first_name}',
            'obj':obj,
            'data':request.user,
            'form':form,
            'eform':eform,
            'editor':user
        }
        return render(request,'manager/edit_user.html',context=data)
    def post(self,request,id,*args ,**kwargs):
        user=User.objects.get(extendedauthuser__user_id__exact=id)
        form=UserProfileChangeForm(request.POST or None,instance=user)
        eform=ExtendedUserProfileChangeForm(request.POST,request.FILES or None,instance=user.extendedauthuser)
        if form.is_valid() and eform.is_valid():
            edituser=form.cleaned_data.get('first_name')+' '+form.cleaned_data.get('last_name')
            role=request.user.extendedauthuser.role
            save_logger(f'Edited user:{edituser}',request.user.get_full_name(),role)
            form.save()
            eform.save()
            return JsonResponse({'valid':True,'message':'data saved'},content_type='application/json')
        else:
            return JsonResponse({'valid':False,'uform_errors':form.errors,'eform_errors':eform.errors,},content_type='application/json')

#delete user
@login_required(login_url='/')
@allowed_users(allowed_roles=['admins'])
def deleteUser(request,id):
    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        try:
            obj=User.objects.get(id=id)
            user=obj.first_name+' '+obj.last_name
            role=request.user.extendedauthuser.role
            save_logger(f'Deleted user:{user}',request.user.get_full_name(),role)
            obj.delete() 
            return JsonResponse({'valid':False,'message':'User deleted successfully.','id':id},content_type='application/json')       
        except User.DoesNotExist:
            return JsonResponse({'valid':True,'message':'User does not exist'},content_type='application/json')


#ProfileView
@method_decorator(login_required(login_url='/'),name='dispatch')
class ProfileView(View):
    def get(self,request,username):
        obj=SiteConstants.objects.all()[0]
        try:
            user=User.objects.get(username__exact=username)
            form=CurrentUserProfileChangeForm(instance=user)
            passform=UserPasswordChangeForm()
            eform=CurrentExtendedUserProfileChangeForm(instance=user.extendedauthuser)
            if request.user.is_superuser:
                eform.fields['role'].choices=[('Admin','View | Edit | Admin'),]
                eform.fields['role'].initial=[0]
            else:
                eform.fields['role'].choices=[('Tertiary','View only'),('Secondary','View | Edit'),('Admin','View | Edit | Admin'),]
                eform.fields['role'].initial=[0]
            data={
                'title':f'Edit profile | {user.first_name}',
                'obj':obj,
                'data':request.user,
                'form':form,
                'eform':eform,
                'editor':user,
                'passform':passform
            }
            return render(request,'manager/profile.html',context=data)
        except User.DoesNotExist:
            return render(request,'manager/404.html',{'title':'Error | Bad Request'},status=400)
 
    def post(self,request,username,*args ,**kwargs):
        form=UserProfileChangeForm(request.POST or None,instance=request.user)
        eform=ExtendedUserProfileChangeForm(request.POST,request.FILES or None,instance=request.user.extendedauthuser)
        if form.is_valid() and eform.is_valid():
            form.save()
            eform.save()
            role=request.user.extendedauthuser.role
            save_logger('Updated profile:',request.user.get_full_name(),role)
            return JsonResponse({'valid':True,'message':'data saved','profile_pic':True},content_type='application/json')
        else:
            return JsonResponse({'valid':False,'uform_errors':form.errors,'eform_errors':eform.errors,},content_type='application/json')


#passwordChange
@login_required(login_url='/')
def passwordChange(request):
    if request.method=='POST' and request.headers.get('x-requested-with') == 'XMLHttpRequest':
        passform=UserPasswordChangeForm(request.POST or None,instance=request.user)
        if passform.is_valid():
            user=User.objects.get(username__exact=request.user.username)
            user.password=make_password(passform.cleaned_data.get('password1'))
            user.save()
            role=request.user.extendedauthuser.role
            save_logger('Changed password :**********',request.user.get_full_name(),role)
            update_session_auth_hash(request,request.user)
            return JsonResponse({'valid':True,'message':'data saved'},content_type='application/json')
        else:
            return JsonResponse({'valid':False,'passform_errors':passform.errors},content_type='application/json')

#NewOrder
@method_decorator(login_required(login_url='/'),name='dispatch')
@method_decorator(allowed_users(allowed_roles=['admins','secondary']),name='dispatch')
class UserNewOrder(View):
    def get(self,request):
        obj=SiteConstants.objects.all()[0]
        orders=Oders.objects.all()
        form=NewOderForm()
        data={
                'title':'Create new order',
                'obj':obj,
                'data':request.user,
                'form':form,
                'orders':orders
            }
        return render(request,'manager/new_order.html',context=data)
    def post(self,request):
        form=NewOderForm(request.POST or None)
        if form.is_valid():
            form.save()
            order=form.cleaned_data.get('ordername')
            role=request.user.extendedauthuser.role
            save_logger(f'Placed a new order:{order}',request.user.get_full_name(),role)
            order_id=OrderFields.objects.latest('id').id
            return JsonResponse({'valid':True,'message':'data saved','order_id':order_id},content_type='application/json')
        else:
            return JsonResponse({'valid':False,'form_errors':form.errors},content_type='application/json')



#view orders
@login_required(login_url='/')
def viewOrders(request):
    obj=SiteConstants.objects.all()[0]
    data=Oders.objects.all().order_by('-ordername_id')
    paginator=Paginator(data,30)
    page_num=request.GET.get('page')
    orders=paginator.get_page(page_num)
    data={
        'title':'View orders',
        'obj':obj,
        'data':request.user,
        'orders':orders,
        'count':paginator.count,
    }
    return render(request,'manager/view_order.html',context=data)

#editMainOrder
@login_required(login_url='/')
@allowed_users(allowed_roles=['admins'])
def editMainOrder(request,id):
    data=Oders.objects.get(ordername_id=id)
    form=NewOderForm(request.POST or None,instance=data)
    if form.is_valid():
        form.save()
        order=form.cleaned_data.get('ordername')
        role=request.user.extendedauthuser.role
        save_logger(f'Edited order:{order}',request.user.get_full_name(),role)
        return JsonResponse({'valid':True,'message':'data saved'},content_type='application/json')
    else:
        return JsonResponse({'valid':False,'form_errors':form.errors},content_type='application/json')



#editOrder
@method_decorator(login_required(login_url='/'),name='dispatch')
@method_decorator(allowed_users(allowed_roles=['admins','secondary']),name='dispatch')
class EditOrder(View):
    def get(self,request,id):
        obj=SiteConstants.objects.all()[0]
        data=OrderFields.objects.get(id=id)
        obj=Oders.objects.get(ordername_id=data.order_id)
        form=OrderFieldsForm(instance=data)
        customers=OrderFields.objects.values('customer').distinct()
        data={
            'title':f'Edit oreder | {obj.ordername}',
            'obj':obj,
            'data':request.user,
            'form':form,
            'editor':obj,
            'form_id':id,
            'customerlist':customers
        }
        return render(request,'manager/tabulate.html',context=data)
    def post(self,request,id):
        data=OrderFields.objects.get(id=id)
        obj=Oders.objects.get(ordername_id=data.order_id)
        form=OrderFieldsForm(request.POST,request.FILES or None,instance=data)
        if form.is_valid():
            t=form.save(commit=False)
            t.modified_at=now()
            t.save()
            order=obj.ordername
            role=request.user.extendedauthuser.role
            save_logger(f'Edited order:{order}',request.user.get_full_name(),role)
            return JsonResponse({'valid':True,'message':'data saved'},content_type='application/json')
        else:
            return JsonResponse({'valid':False,'form_errors':form.errors},content_type='application/json')


@login_required(login_url='/')
def viewOrder(request,id):
    obj=SiteConstants.objects.all()[0]
    data=Oders.objects.all().order_by('-id')
    paginator=Paginator(data,30)
    page_num=request.GET.get('page')
    orders=paginator.get_page(page_num)
    data={
        'title':'View orders',
        'obj':obj,
        'data':request.user,
        'orders':orders,
        'count':paginator.count,
    }
    return render(request,'manager/view_order.html',context=data)


#deleteOrder
@login_required(login_url='/')
@allowed_users(allowed_roles=['admins'])
def deleteOrder(request,id):
    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        try:
            obj=Oders.objects.get(orderfields__order_id__exact=id)
            order=obj.ordername
            role=request.user.extendedauthuser.role
            save_logger(f'Deleted order:{order}',request.user.get_full_name(),role)
            obj.delete() 
            return JsonResponse({'valid':False,'message':'Order deleted successfully.','id':id},content_type='application/json')       
        except Oders.DoesNotExist:
            return JsonResponse({'valid':True,'message':'Order does not exist'},content_type='application/json')

#tabulateOrder
@method_decorator(login_required(login_url='/'),name='dispatch')
@method_decorator(allowed_users(allowed_roles=['admins','secondary']),name='dispatch')
class TabulateOrder(View):
    def get(self,request,id):
        try:
            obj=SiteConstants.objects.all()[0]
            order=OrderFields.objects.get(id__exact=id)
            orders=Oders.objects.get(ordername_id__exact=order.order_id)
            form=OrderFieldsForm()
            customers=OrderFields.objects.all()
            data={
                'title':f'Edit order | {orders.ordername}',
                'obj':obj,
                'data':request.user,
                'editor':orders,
                'form':form,
                'form_id':id,
                'customers':customers
            }
            return render(request,'manager/tabulate.html',context=data)
        except User.DoesNotExist:
            return render(request,'manager/404.html',{'title':'Error | Bad Request'},status=400)
    
    def post(self,request,id):
        order=OrderFields.objects.get(id__exact=id)
        orders=Oders.objects.get(ordername_id__exact=order.order_id)
        form=OrderFieldsForm(request.POST,request.FILES or None,instance=order)
        if form.is_valid():
            form.save()
            order=orders.ordername
            role=request.user.extendedauthuser.role
            save_logger(f'Tabulated order:{order}',request.user.get_full_name(),role)
            return JsonResponse({'valid':True,'message':'data saved'},content_type='application/json')
        else:
            return JsonResponse({'valid':False,'form_errors':form.errors},content_type='application/json')

@register.filter
def sort_file_type(item):
    print(item)
    

#orderSummary
@login_required(login_url='/')
def orderSummary(request):
    obj=SiteConstants.objects.all()[0]
    now=datetime.datetime.now()
    orders=OrderFields.objects.all().order_by('prefix')
    paginator=Paginator(orders,30)
    page_num=request.GET.get('page')
    orders=paginator.get_page(page_num)
    form=FormUploads()
    data={
        'title':'All orders summary',
        'obj':obj,
        'data':request.user,
        'orders':orders,
        'count':paginator.count,
        'form':form
    }
    return render(request,'manager/order_summary.html',context=data)

#deleteSingleItem
@login_required(login_url='/')
@allowed_users(allowed_roles=['admins','secondary'])
def deleteSingleItem(request,id):
    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        try:
            obj=Oders.objects.get(orderfields__id=id)
            order=obj.ordername
            role=request.user.extendedauthuser.role
            save_logger(f'Deleted  order:{order}',request.user.get_full_name(),role)
            obj.delete() 
            return JsonResponse({'valid':False,'message':'Order item deleted successfully.','id':id},content_type='application/json')       
        except Oders.DoesNotExist:
            return JsonResponse({'valid':True,'message':'User does not exist'},content_type='application/json')

#create file size
def convert_file_size(size_bytes):
    if size_bytes == 0:
        return '0B'
    size_name=('B','KB','MB','GB','TB','PB','EB','ZB','YB')
    i=int(math.floor(math.log(size_bytes,1024)))
    p=math.pow(1024,i)
    s=round(size_bytes / p,2)
    return "%s %s" % (s,size_name[i])


#handleUpload
@login_required(login_url='/')
def handleUpload(request,id):
    if request.method == 'POST':
        ob=OrderFields.objects.get(id__exact=id)
        form=FormUploads(request.POST,request.FILES or None,instance=ob)
        if form.is_valid():
            t=form.save(commit=False)
            file_media=request.FILES['media']
            fss=FileSystemStorage()
            file_type=file_media.name.split('.')[1]
            file_size=convert_file_size(file_media.size)
            filename01=fss.save(file_media.name,file_media)
            file_media_url=fss.url(filename01)
            t.media=file_media
            t.file_size=file_size
            t.file_type=file_type
            t.save()
            file=file_media.name
            role=request.user.extendedauthuser.role
            save_logger(f'Uploaded file:{file}',request.user.get_full_name(),role)
            return JsonResponse({'valid':False,'message':'File saved successfully.'},content_type='application/json')
        else:       
            return JsonResponse({'valid':True,'message':'User does not exist'},content_type='application/json')



#UserUploads
@login_required(login_url='/')
@allowed_users(allowed_roles=['admins'])
def UserUploads(request):
    obj=SiteConstants.objects.all()[0]
    orders=OrderFields.objects.filter(media__isnull=False).all().order_by('-id')
    paginator=Paginator(orders,30)
    page_num=request.GET.get('page')
    orders=paginator.get_page(page_num)
    data={
            'title':'File uploads',
            'obj':obj,
            'data':request.user,
            'count':paginator.count,
            'files':orders,
    }
    return render(request,'manager/uploads.html',context=data)


#UserUploadsDelete
@login_required(login_url='/')
def UserUploadsDelete(request,id):
    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        try:
            obj=OrderFields.objects.get(id=id)
            file=obj.media.name
            role=request.user.extendedauthuser.role
            save_logger(f'Deleted uploaded file:{file}',request.user.get_full_name(),role)
            obj.delete() 
            return JsonResponse({'valid':False,'message':'File deleted successfully.','id':id},content_type='application/json')       
        except UserFileUploads.DoesNotExist:
            return JsonResponse({'valid':True,'message':'File does not exist'},content_type='application/json')


#CustomerQuote
class CustomerQuote(View):
    def get(self,request):
        obj=SiteConstants.objects.all()[0]
        form=CustomerForm()
        data={
            'title':'Customer Quote',
            'obj':obj,
            'data':request.user,
            'form':form,
        }
        return render(request,'manager/customer.html',context=data)
    def post(self,request):
        form=CustomerForm(request.POST,request.FILES or None)
        if form.is_valid():
            form.save()
            email=request.POST['quote_email']
            save_logger(f'Customer  placed a new quote  with quote email:{email}',email)
            return JsonResponse({'valid':True,'message':'data saved'},content_type='application/json')
        else:
            return JsonResponse({'valid':False,'form_errors':form.errors},content_type='application/json')

#incomings
@login_required(login_url='/')
@allowed_users(allowed_roles=['admins','secondary','tertiary'])
def incomings(request):
    obj=SiteConstants.objects.all()[0]
    quotes=CustomerFields.objects.all().order_by('-id')
    paginator=Paginator(quotes,30)
    page_num=request.GET.get('page')
    total_quotes=paginator.get_page(page_num)
    data={
        'title':'Customers Incomings',
        'obj':obj,
        'data':request.user,
        'orders':total_quotes
    }
    return render(request,'manager/incomings.html',context=data)





@method_decorator(login_required(login_url='/'),name='dispatch')
@method_decorator(allowed_users(allowed_roles=['admins','secondary']),name='dispatch')
class QuoteEditView(View):
    def get(self,request,id):
        obj=SiteConstants.objects.all()[0]
        data=CustomerFields.objects.get(id=id)
        form=CustomerForm(instance=data)
        data={
            'title':'Edit Quote',
            'obj':obj,
            'data':request.user,
            'form':form,
            'form_id':id,
        }
        return render(request,'manager/edit_quote.html',context=data)
    def post(self,request,id):
        data=CustomerFields.objects.get(id__exact=id)
        form=CustomerForm(request.POST,request.FILES or None,instance=data)
        if form.is_valid():
            t=form.save(commit=False)
            t.modified_at=now()
            t.save()
            email=request.POST['quote_email']
            role=request.user.extendedauthuser.role
            save_logger(f'Edited customer quoted form data of quote email:{email}',request.user.get_full_name(),role)
            return JsonResponse({'valid':True,'message':'data saved'},content_type='application/json')
        else:
            return JsonResponse({'valid':False,'form_errors':form.errors},content_type='application/json')


#deleteQuote
@login_required(login_url='/')
@allowed_users(allowed_roles=['admins',])
def deleteQuote(request,id):
    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        try:
            obj=CustomerFields.objects.get(id__exact=id)
            email=obj.quote_email
            role=request.user.extendedauthuser.role
            save_logger(f'Deleted customer of quote email:{email}',request.user.get_full_name(),role)
            obj.delete() 
            return JsonResponse({'valid':False,'message':'Quote deleted successfully.','id':id},content_type='application/json')       
        except Oders.DoesNotExist:
            return JsonResponse({'valid':True,'message':'Quote does not exist'},content_type='application/json')

#handleUpload
@login_required(login_url='/')
def UploadMedia(request,id):
    if request.method == 'POST':
        ob=CustomerFields.objects.get(id__exact=id)
        form=CustomerUploads(request.POST,request.FILES or None,instance=ob)
        if form.is_valid():
            t=form.save(commit=False)
            file_media=request.FILES['media']
            fss=FileSystemStorage()
            filename01=fss.save(file_media.name,file_media)
            file_media_url=fss.url(filename01)
            t.media=file_media
            t.save()
            media=file_media.name
            role=request.user.extendedauthuser.role
            save_logger(f'Uploaded media:{media}',request.user.get_full_name(),role)
            return JsonResponse({'valid':False,'message':'File saved successfully.'},content_type='application/json')
        else:       
            return JsonResponse({'valid':True,'message':'User does not exist'},content_type='application/json')


#customerView
def customerView(request,authlink):
    obj=SiteConstants.objects.all()[0]
    try:
        q=OrderFields.objects.get(customer_link=authlink)
        quotes=OrderFields.objects.filter(id=q.id).order_by('-id')
        paginator=Paginator(quotes,30)
        page_num=request.GET.get('page')
        results=paginator.get_page(page_num)
        data={
                'title':'Customer status update',
                'obj':obj,
                'data':request.user,
                'orders':results,
                'count':paginator.count
            }
        return render(request,'manager/status.html',context=data)
    except OrderFields.DoesNotExist:
        data={
                'title':'Error | Page Not Found',
                'obj':obj
        }
        return render(request,'manager/404.html',context=data,status=404)

#logs

@login_required(login_url='/')
@allowed_users(allowed_roles=['admins'])
def logs(request):
    obj=SiteConstants.objects.all()[0]
    data=LoggerData.objects.all().order_by('-id')
    paginator=Paginator(data,30)
    page_num=request.GET.get('page')
    results=paginator.get_page(page_num)
    data={
            'title':'Customer status update',
            'obj':obj,
            'data':request.user,
            'logs':results,
            'count':paginator.count
        }
    return render(request,'manager/logger.html',context=data)



def generate_id():
    return get_random_string(6,'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKMNOPQRSTUVWXYZ0123456789')
#AuthLink
class AuthLink(View):
    def get(self,request):
        obj=SiteConstants.objects.all()[0]
        form=AuthForm()
        data={
            'title':'Resseting authorization link',
            'obj':obj,
            'data':request.user,
            'form':form,
        }
        return render(request,'manager/auth_link.html',context=data)
    def post(self,request):
        obj=SiteConstants.objects.all()[0]
        form=AuthForm(request.POST or None)
        if form.is_valid():
            dg=OrderFields.objects.get(customer_email=form.cleaned_data.get('email'))
            dg.customer_link=generate_id
            dg.save()
            subject='Authorization link.'
            email=form.cleaned_data.get('email')
            user=email.split('@')[0]
            message={
                        'user':user,
                        'site_name':obj.site_name,
                        'site_url':obj.site_url,
                        'link':generate_id
                    }
            template='emails/auth_link.html'
            send_email(subject,email,message,template)
            save_logger(f'Customer requested for a new authorization link with quote email:{email}',email)
            return JsonResponse({'valid':True,'message':'link sent successfully'},content_type='application/json')
        else:
            return JsonResponse({'valid':False,'form_errors':form.errors},content_type='application/json')

#authLinkSent
def authLinkSent(request):
    obj=SiteConstants.objects.all()[0]
    data={
        'title':'Authorization link Sent!',
        'obj':obj,
        'data':request.user,
    }
    return render(request,'manager/success.html',context=data)

#deleteLog
@login_required(login_url='/')
@allowed_users(allowed_roles=['admins'])
def deleteLog(request,id):
    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        try:
            obj=LoggerData.objects.get(id=id)
            obj.delete() 
            return JsonResponse({'valid':False,'message':'Log deleted successfully.','id':id},content_type='application/json')       
        except LoggerData.DoesNotExist:
            return JsonResponse({'valid':True,'message':'Log does not exist'},content_type='application/json')

#deleteAllLogs
@login_required(login_url='/')
@allowed_users(allowed_roles=['admins'])
def deleteAllLogs(request):
    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        try:
            obj=LoggerData.objects.all()
            obj.delete() 
            return JsonResponse({'valid':False,'message':'Logs deleted successfully.','id':id},content_type='application/json')       
        except Exception as e:
            return JsonResponse({'valid':True,'message':'Error: Something went wrong'},content_type='application/json')
