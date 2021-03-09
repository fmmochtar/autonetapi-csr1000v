from django.contrib import admin
from .models import Device, Log, AttackLog, AccessControlID, Attacker

admin.site.site_header = "AutonetAPI Administration"
admin.site.site_title = "AutonetAPI"
admin.site.index_title = "Site Administration"

# Register your models here.

admin.site.register(Device)
admin.site.register(AccessControlID)
admin.site.register(Attacker)
admin.site.register(Log)
admin.site.register(AttackLog)