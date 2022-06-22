from django.contrib import admin
from import_export.admin import ImportExportModelAdmin
# Register your models here.
from .models import Oders

@admin.register(Oders)
class OrderAdmin(ImportExportModelAdmin):
    pass

