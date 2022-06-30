from django.contrib import admin
from import_export import resources
from import_export.admin import ImportExportModelAdmin
from .models import OrderModel

class OrderResource(resources.ModelResource):
    class Meta:
        model=OrderModel
        import_id_fields=('order_id',)
        fields=[
                'order_id','ordername_serial','ordername','prefix','container','status',
                'date','pierpass','pierpass_dolla','exam','mbl','hbl','customer','ship_to','type','seal','drop_city',
                'discharge_port','port_eta','lfd','trucking','appointment','actual_deliver','full_out_driver','empty_return',
                'empty_in_driver','chasis','demurrage','demurrage_dolla','do_recd','invoice_sent','invoice','invoice_dolla',
                'per_diem','sml','a_rrry','a_ppy','customer_email','notify','acct_email','customer_link','comment','media','file_size',
                'file_type','action','role','user','modified_at','created_at'
            ]

@admin.register(OrderModel)
class OrderAdmin(ImportExportModelAdmin):
    resource_class=OrderResource


