from django.contrib import admin
from import_export.admin import ImportExportModelAdmin
# Register your models here.
from .models import OrderModel

@admin.register(OrderModel)
class OrderAdmin(ImportExportModelAdmin):
    pass

