import re
from django.contrib.auth.models import User,Group
from .models import OrderModel


#searchStore
def searchOrderItems(search):
    if search:
        if OrderModel.objects.filter(container__icontains=search).exists():
            results=OrderModel.objects.filter(container__icontains=search)
            return results
        elif OrderModel.objects.filter(load__icontains=search).exists():
            results=OrderModel.objects.filter(load__icontains=search)
            return results
        elif OrderModel.objects.filter(ordername__icontains=search).exists():
            results=OrderModel.objects.filter(ordername__icontains=search)
            return results
        elif OrderModel.objects.filter(status__icontains=search).exists():
            results=OrderModel.objects.filter(status__icontains=search)
            return results
        elif OrderModel.objects.filter(date__icontains=search).exists():
            results=OrderModel.objects.filter(date__icontains=search)
            return results
        elif OrderModel.objects.filter(pierpass__icontains=search).exists():
            results=OrderModel.objects.filter(pierpass__icontains=search)
            return results
        elif OrderModel.objects.filter(pierpass_dolla__icontains=search).exists():
            results=OrderModel.objects.filter(pierpass_dolla__icontains=search)

        elif OrderModel.objects.filter(exam__icontains=search).exists():
            results=OrderModel.objects.filter(exam__icontains=search)
            return results

        elif OrderModel.objects.filter(mbl__icontains=search).exists():
            results=OrderModel.objects.filter(mbl__icontains=search)
            return results
        elif OrderModel.objects.filter(customer__icontains=search).exists():
            results=OrderModel.objects.filter(customer__icontains=search)
            return results
        elif OrderModel.objects.filter(ship_to__icontains=search).exists():
            results=OrderModel.objects.filter(ship_to__icontains=search)
            return results
        elif OrderModel.objects.filter(type__icontains=search).exists():
            results=OrderModel.objects.filter(type__icontains=search)
            return results
        elif OrderModel.objects.filter(seal__icontains=search).exists():
            results=OrderModel.objects.filter(seal__icontains=search)
            return results
        elif OrderModel.objects.filter(drop_city__icontains=search).exists():
            results=OrderModel.objects.filter(drop_city__icontains=search)
            return results
        elif OrderModel.objects.filter(discharge_port__icontains=search).exists():
            results=OrderModel.objects.filter(discharge_port__icontains=search)
            return results
        elif OrderModel.objects.filter(port_eta__icontains=search).exists():
            results=OrderModel.objects.filter(port_eta__icontains=search)
            return results
        elif OrderModel.objects.filter(lfd__icontains=search).exists():
            results=OrderModel.objects.filter(lfd__icontains=search)
            return results
        elif OrderModel.objects.filter(trucking__icontains=search).exists():
            results=OrderModel.objects.filter(trucking__icontains=search)
            return results
        elif OrderModel.objects.filter(appointment__icontains=search).exists():
            results=OrderModel.objects.filter(appointment__icontains=search)
            return results
        elif OrderModel.objects.filter(actual_deliver__icontains=search).exists():
            results=OrderModel.objects.filter(actual_deliver__icontains=search)
            return results
        elif OrderModel.objects.filter(full_out_driver__icontains=search).exists():
            results=OrderModel.objects.filter(full_out_driver__icontains=search)
            return results
        elif OrderModel.objects.filter(empty_return__icontains=search).exists():
            results=OrderModel.objects.filter(empty_return__icontains=search)
            return results
        elif OrderModel.objects.filter(empty_in_driver__icontains=search).exists():
            results=OrderModel.objects.filter(empty_in_driver__icontains=search)
            return results
        elif OrderModel.objects.filter(chasis__icontains=search).exists():
            results=OrderModel.objects.filter(chasis__icontains=search)
            return results
        elif OrderModel.objects.filter(demurrage__icontains=search).exists():
            results=OrderModel.objects.filter(demurrage__icontains=search)
            return results
        elif OrderModel.objects.filter(demurrage_dolla__icontains=search).exists():
            results=OrderModel.objects.filter(demurrage_dolla__icontains=search)
            return results
        elif OrderModel.objects.filter(do_recd__icontains=search).exists():
            results=OrderModel.objects.filter(do_recd__icontains=search)
            return results
        elif OrderModel.objects.filter(invoice_sent__icontains=search).exists():
            results=OrderModel.objects.filter(invoice_sent__icontains=search)
            return results
        elif OrderModel.objects.filter(invoice__icontains=search).exists():
            results=OrderModel.objects.filter(invoice__icontains=search)
            return results
        elif OrderModel.objects.filter(invoice_dolla__icontains=search).exists():
            results=OrderModel.objects.filter(invoice_dolla__icontains=search)
            return results
        elif OrderModel.objects.filter(per_diem__icontains=search).exists():
            results=OrderModel.objects.filter(per_diem__icontains=search)
            return results
        elif OrderModel.objects.filter(sml__icontains=search).exists():
            results=OrderModel.objects.filter(sml__icontains=search)
            return results
        elif OrderModel.objects.filter(a_rrry__icontains=search).exists():
            results=OrderModel.objects.filter(a_rrry__icontains=search)
            return results
        elif OrderModel.objects.filter(a_ppy__icontains=search).exists():
            results=OrderModel.objects.filter(a_ppy__icontains=search)
            return results
        elif OrderModel.objects.filter(customer_email__icontains=search).exists():
            results=OrderModel.objects.filter(customer_email__icontains=search)
            return results
        elif OrderModel.objects.filter(notify__icontains=search).exists():
            results=OrderModel.objects.filter(notify__icontains=search)
            return results
        elif OrderModel.objects.filter(acct_email__icontains=search).exists():
            results=OrderModel.objects.filter(acct_email__icontains=search)
            return results
        else:
            return False