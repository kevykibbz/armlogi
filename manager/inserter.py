#insertView
def insertView(request):
    data={
            'ordername':'old data',
            'user':request.user.get_full_name(),
            'role':request.user.extendedauthuser.role,
            'action':'migrated old data'

        }

    for x in range(1,2):
        obj=Oders.objects.create(ordername=data['ordername'],user=data['user'],role=data['role'],action=data['action'])
        obj.save()
    else:
        return HttpResponse('data saved successfully')