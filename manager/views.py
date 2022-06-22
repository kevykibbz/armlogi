from manager.decorators import unauthenticated_user,allowed_users
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from .models import ExtendedAuthUser,OrderModel,UserFileUploads,CustomerFields,LoggerData,OrderLogs
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
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
import csv
from django.templatetags.static import static
#save logger data
def save_logger(action,user,role):
    if action and user:
        y=LoggerData.objects.create(action=action,user=user,role=role)
        y.save()

#save order logs
def save_order_logger(post_data,order_id,user,action,role):
    data=OrderModel.objects.get(id=order_id)
    form=OrderFieldsFormLogs(post_data , instance=data)
    if form.is_valid():
        output=OrderLogs.objects.create(
                                            user=user,
                                            action=action,
                                            order_id=order_id,
                                            role=role,
                                            status=form.cleaned_data.get('status'),
                                            pierpass=form.cleaned_data.get('pierpass'),
                                            pierpass_dolla=form.cleaned_data.get('pierpass_dolla'),
                                            exam=form.cleaned_data.get('exam'),
                                            mbl=form.cleaned_data.get('mbl'),
                                            hbl=form.cleaned_data.get('hbl'),
                                            customer=form.cleaned_data.get('customer'),
                                            ship_to=form.cleaned_data.get('ship_to'),
                                            container=form.cleaned_data.get('container'),
                                            type=form.cleaned_data.get('type'),
                                            seal=form.cleaned_data.get('seal'),
                                            drop_city=form.cleaned_data.get('drop_city'),
                                            discharge_port=form.cleaned_data.get('discharge_port'),
                                            port_eta=form.cleaned_data.get('port_eta'),
                                            lfd=form.cleaned_data.get('lfd'),
                                            trucking=form.cleaned_data.get('trucking'),
                                            east_deliver=form.cleaned_data.get('east_deliver'),
                                            appointment=form.cleaned_data.get('appointment'),
                                            actual_deliver=form.cleaned_data.get('actual_deliver'),
                                            full_out_driver=form.cleaned_data.get('full_out_driver'),
                                            empty_return=form.cleaned_data.get('empty_return'),
                                            empty_in_driver=form.cleaned_data.get('empty_in_driver'),
                                            chasis=form.cleaned_data.get('chasis'),
                                            demurrage=form.cleaned_data.get('demurrage'), 
                                            demurrage_dolla=form.cleaned_data.get('demurrage_dolla'),
                                            do_recd=form.cleaned_data.get('do_recd'),
                                            invoice_sent=form.cleaned_data.get('invoice_sent'),
                                            invoice=form.cleaned_data.get('invoice'),
                                            invoice_dolla=form.cleaned_data.get('invoice_dolla'),
                                            per_diem=form.cleaned_data.get('per_diem'),
                                            sml=form.cleaned_data.get('sml'),
                                            a_rrry=form.cleaned_data.get('a_rrry'),
                                            a_ppy=form.cleaned_data.get('a_ppy'),
                                            customer_email=form.cleaned_data.get('customer_email'),
                                            notify=form.cleaned_data.get('notify'),
                                            acct_email=form.cleaned_data.get('acct_email'),
                                            date=form.cleaned_data.get('date'),
                                            media=form.cleaned_data.get('media'),
                                            comment=form.cleaned_data.get('comment')
        )
        output.save()

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
    orders_count=OrderModel.objects.count()
    completed_orders=OrderModel.objects.filter(status__icontains='delivered').count()
    cancelled_orders=OrderModel.objects.filter(status__icontains='cancelled').count()
    orders=OrderModel.objects.all().order_by('-modified_at')[:12]
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
        orders=OrderModel.objects.all()
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
        obj=SiteConstants.objects.all()[0]
        form=NewOderForm(request.POST or None)
        if form.is_valid():
            role=request.user.extendedauthuser.role
            order=form.cleaned_data.get('ordername')
            action=f'Placed a new order:{order}'
            y=form.save(commit=False)
            y.user=request.user.get_full_name()
            y.action=action
            y.role=role
            y.save()
            save_logger(action,request.user.get_full_name(),role)
            order_id=OrderModel.objects.latest('id').id
            return JsonResponse({'valid':True,'message':'data saved','order_id':order_id},content_type='application/json')
        else:
            return JsonResponse({'valid':False,'form_errors':form.errors},content_type='application/json')



#view orders
@login_required(login_url='/')
def viewOrders(request):
    obj=SiteConstants.objects.all()[0]
    data=OrderModel.objects.all().order_by('-id')
    paginator=Paginator(data,30)
    page_num=request.GET.get('page')
    orders=paginator.get_page(page_num)
    print(orders)
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
    data=OrderModel.objects.get(id__exact=id)
    form=NewOderForm(request.POST or None,instance=data)
    if form.is_valid():
        order=form.cleaned_data.get('ordername')
        form.save()
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
        data=OrderModel.objects.get(id=id)
        form=OrderFieldsForm(instance=data)
        customers=OrderModel.objects.values('customer').distinct()
        data={
            'title':f'Edit order | {data.ordername}',
            'obj':obj,
            'data':request.user,
            'form':form,
            'editor':data,
            'form_id':id,
            'link':data.customer_link,
            'customerlist':customers
        }
        return render(request,'manager/tabulate.html',context=data)
    def post(self,request,id):
        data=OrderModel.objects.get(id=id)
        site_data=SiteConstants.objects.all()[0]
        form=OrderFieldsForm(request.POST,request.FILES or None,instance=data)
        if form.is_valid():
            if form.has_changed():
                order=data.ordername
                container=data.container if data.container else 'No container data was provided'
                load=data.load if data.load else 'No load data found'
                action=f'Edited order:{order},container :{container},load:{load}'
                user=request.user.get_full_name()
                role=request.user.extendedauthuser.role
                t=form.save(commit=False)
                save_order_logger(request.POST,id,user,action,role)
                t.modified_at=now()
                t.customer_link=generate_id()
                t.prefix='21A'+str(id).zfill(5)
                t.user=request.user.get_full_name()
                t.action=action
                t.role=request.user.extendedauthuser.role
                t.save()
                role=request.user.extendedauthuser.role
                save_logger(action,request.user.get_full_name(),role)
                return JsonResponse({'valid':True,'message':'data saved'},content_type='application/json')
            else:
                return JsonResponse({'valid':False,'error':'No changes made'},content_type='application/json')
        else:
            return JsonResponse({'valid':False,'form_errors':form.errors},content_type='application/json')


@login_required(login_url='/')
def viewOrder(request,id):
    obj=SiteConstants.objects.all()[0]
    data=OrderModel.objects.all().order_by('-id')
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
            obj=OrderModel.objects.get(id__exact=id)
            order=obj.ordername
            role=request.user.extendedauthuser.role
            save_logger(f'Deleted order:{order}',request.user.get_full_name(),role)
            obj.delete() 
            return JsonResponse({'valid':False,'message':'Order deleted successfully.','id':id},content_type='application/json')       
        except OrderModel.DoesNotExist:
            return JsonResponse({'valid':True,'message':'Order does not exist'},content_type='application/json')

#tabulateOrder
@method_decorator(login_required(login_url='/'),name='dispatch')
@method_decorator(allowed_users(allowed_roles=['admins','secondary']),name='dispatch')
class TabulateOrder(View):
    def get(self,request,id):
        try:
            obj=SiteConstants.objects.all()[0]
            order=OrderModel.objects.get(id__exact=id)
            form=OrderFieldsForm()
            customers=OrderModel.objects.all()
            data={
                'title':f'Edit order | {order.ordername}',
                'obj':obj,
                'data':request.user,
                'editor':order,
                'form':form,
                'form_id':id,
                'customers':customers
            }
            return render(request,'manager/tabulate.html',context=data)
        except User.DoesNotExist:
            return render(request,'manager/404.html',{'title':'Error | Bad Request'},status=400)
    
    def post(self,request,id):
        order=OrderModel.objects.get(id__exact=id)
        form=OrderFieldsForm(request.POST,request.FILES or None,instance=order)
        if form.is_valid():
            form.save()
            order=order.ordername
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
    orders=OrderModel.objects.all().order_by('prefix')
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
            obj=OrderModel.objects.get(id__exact=id)
            order=obj.ordername
            role=request.user.extendedauthuser.role
            save_logger(f'Deleted  order:{order}',request.user.get_full_name(),role)
            obj.delete() 
            return JsonResponse({'valid':False,'message':'Order item deleted successfully.','id':id},content_type='application/json')       
        except OrderModel.DoesNotExist:
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
        ob=OrderModel.objects.get(id__exact=id)
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
    orders=OrderModel.objects.filter(media__isnull=False).all().order_by('-id')
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
            obj=OrderModel.objects.get(id=id)
            file=obj.media.name
            role=request.user.extendedauthuser.role
            save_logger(f'Deleted uploaded file:{file}',request.user.get_full_name(),role)
            obj.delete() 
            return JsonResponse({'valid':False,'message':'File deleted successfully.','id':id},content_type='application/json')       
        except OrderModel.DoesNotExist:
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
            role='Customer'
            save_logger(f'Customer  placed a new quote  with quote email:{email}',email,role)
            return JsonResponse({'valid':True,'message':'data saved'},content_type='application/json')
        else:
            return JsonResponse({'valid':False,'form_errors':form.errors},content_type='application/json')

#CustomerIncoming
@method_decorator(login_required(login_url='/'),name='dispatch')
@method_decorator(allowed_users(allowed_roles=['admins','secondary']),name='dispatch')
class CustomerIncoming(View):
    def get(self,request):
        obj=SiteConstants.objects.all()[0]
        form=DoIncomingsForm()
        data={
            'title':'Customer Incoming',
            'obj':obj,
            'data':request.user,
            'form':form,
        }
        return render(request,'manager/customer_incoming.html',context=data)
    def post(self,request):
        form=DoIncomingsForm(request.POST,request.FILES or None)
        if form.is_valid():
            form.save()
            role=request.user.extendedauthuser.role
            save_logger('Placed a new incoming form data.',request.user.get_full_name(),role)
            return JsonResponse({'valid':True,'message':'data saved'},content_type='application/json')
        else:
            return JsonResponse({'valid':False,'form_errors':form.errors},content_type='application/json')

#quotations
@login_required(login_url='/')
@allowed_users(allowed_roles=['admins','secondary','tertiary'])
def quotations(request):
    obj=SiteConstants.objects.all()[0]
    quotes=CustomerFields.objects.all().order_by('-id')
    paginator=Paginator(quotes,30)
    page_num=request.GET.get('page')
    total_quotes=paginator.get_page(page_num)
    data={
        'title':'Customers Quotations',
        'obj':obj,
        'data':request.user,
        'orders':total_quotes
    }
    return render(request,'manager/quotations.html',context=data)

#incomings
@login_required(login_url='/')
@allowed_users(allowed_roles=['admins','secondary','tertiary'])
def incomings(request):
    obj=SiteConstants.objects.all()[0]
    quotes=DoIncomingsModel.objects.all().order_by('-id')
    paginator=Paginator(quotes,30)
    page_num=request.GET.get('page')
    total_quotes=paginator.get_page(page_num)
    data={
        'title':'Customers Incomings',
        'obj':obj,
        'data':request.user,
        'incomings':total_quotes
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

#IncomingEditView
@method_decorator(login_required(login_url='/'),name='dispatch')
@method_decorator(allowed_users(allowed_roles=['admins','secondary']),name='dispatch')
class IncomingEditView(View):
    def get(self,request,id):
        obj=SiteConstants.objects.all()[0]
        data=DoIncomingsModel.objects.get(id__exact=id)
        form=DoIncomingsForm(instance=data)
        data={
            'title':'Edit Incoming',
            'obj':obj,
            'data':request.user,
            'form':form,
            'form_id':id,
        }
        return render(request,'manager/edit_incoming.html',context=data)
    def post(self,request,id):
        data=DoIncomingsModel.objects.get(id__exact=id)
        form=DoIncomingsForm(request.POST,request.FILES or None,instance=data)
        if form.is_valid():
            t=form.save(commit=False)
            t.modified_at=now()
            t.save()
            role=request.user.extendedauthuser.role
            save_logger('Edited customer incoming form data.',request.user.get_full_name(),role)
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
        except CustomerFields.DoesNotExist:
            return JsonResponse({'valid':True,'message':'Quote does not exist'},content_type='application/json')
#deleteIncoming
@login_required(login_url='/')
@allowed_users(allowed_roles=['admins',])
def deleteIncoming(request,id):
    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        try:
            obj=DoIncomingsModel.objects.get(id__exact=id)
            role=request.user.extendedauthuser.role
            save_logger('Deleted incoming form data.',request.user.get_full_name(),role)
            obj.delete() 
            return JsonResponse({'valid':False,'message':'Incoming form deleted successfully.','id':id},content_type='application/json')       
        except DoIncomingsModel.DoesNotExist:
            return JsonResponse({'valid':True,'message':'Incoming form data does not exist'},content_type='application/json')

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
        quotes=OrderModel.objects.get(customer_link=authlink)
        data={
                'title':'Customer status update',
                'obj':obj,
                'data':request.user,
                'orders':quotes,
            }
        return render(request,'manager/status.html',context=data)
    except OrderModel.DoesNotExist:
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
            dg=OrderModel.objects.get(customer_email=form.cleaned_data.get('email'))
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
            role='Customer'
            save_logger(f'Customer requested for a new authorization link with quote email:{email}',email,role)
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
            return JsonResponse({'valid':True,'message':'Log deleted successfully.','id':id},content_type='application/json')       
        except LoggerData.DoesNotExist:
            return JsonResponse({'valid':False,'message':'Log does not exist'},content_type='application/json')

#deleteOrderLog

@login_required(login_url='/')
@allowed_users(allowed_roles=['admins'])
def deleteOrderLog(request,id):
    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        try:
            obj=OrderLogs.objects.get(id=id)
            obj.delete() 
            return JsonResponse({'valid':True,'message':'Log deleted successfully.','id':id},content_type='application/json')       
        except OrderLogs.DoesNotExist:
            return JsonResponse({'valid':False,'message':'Order log does not exist'},content_type='application/json')

#deleteAllLogs
@login_required(login_url='/')
@allowed_users(allowed_roles=['admins'])
def deleteAllLogs(request):
    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        try:
            obj=LoggerData.objects.all()
            obj.delete() 
            return JsonResponse({'valid':True,'message':'Logs deleted successfully.','id':id},content_type='application/json')       
        except Exception as e:
            return JsonResponse({'valid':False,'message':'Error: Something went wrong'},content_type='application/json')


#deleteAllOrderLogs
@login_required(login_url='/')
@allowed_users(allowed_roles=['admins'])
def deleteAllOrderLogs(request):
    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        try:
            obj=OrderLogs.objects.all()
            obj.delete() 
            return JsonResponse({'valid':True,'message':'Order ogs deleted successfully.','id':id},content_type='application/json')       
        except Exception as e:
            return JsonResponse({'valid':False,'message':'Error: Something went wrong'},content_type='application/json')



#OrderLogs

@login_required(login_url='/')
@allowed_users(allowed_roles=['admins'])
def OrderLogger(request,id): 
    try:
        obj=SiteConstants.objects.all()[0]
        a=OrderModel.objects.get(id=id)
        data=OrderLogs.objects.filter(order_id=id).order_by('-id')
        paginator=Paginator(data,30)
        page_num=request.GET.get('page')
        results=paginator.get_page(page_num)
        data={
                'title':f'{a.ordername} recent logs',
                'obj':obj,
                'data':request.user,
                'logs':results,
                'count':paginator.count,
                'ordername':a.ordername,
                'order_id':id
            }
        return render(request,'manager/order_logger.html',context=data)     
    except Exception as e:
        data={
                'title':'Error | Page Not Found',
                'obj':obj
        }
        return render(request,'manager/404.html',context=data,status=404)

#send_notification
@csrf_exempt
@login_required(login_url='/')
@allowed_users(allowed_roles=['admins','secondary'])
def send_notification(request):
    id=request.POST['id']
    data=OrderModel.objects.get(id__exact=id)
    obj=SiteConstants.objects.all()[0]
    if data.customer_link and data.customer_email:
        try:
            subject='Authorization link.'
            domain=settings.BASE_URL
            email=data.customer_email
            link=data.customer_link
            message={

                    'link':link,
                    'domain':domain,
                    'site_name':obj.site_name,
                    'site_url':obj.site_url,
            }
            template='emails/auth_link.html'
            send_email(subject,email,message,template)
            return JsonResponse({'valid':True,'message':'Notification sent successfully'},content_type='application/json')
        except Exception as e:
            return JsonResponse({'valid':False,'message':'Error: Something went wrong'},content_type='application/json')       
    return JsonResponse({'valid':False,'message':'Error: Update Customer Email First.'},content_type='application/json')       


#insertView
def insertView(request):
    file=open(static('data.csv'))
    csvreader=csv.reader(file)
    rows=[]
    d=dict()
    for row in csvreader:
        rows.append(row)
    for r in rows:
        d.update({r[0]:r[1]})
        print(r[0])
    file.close()