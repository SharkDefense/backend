from django.contrib import admin
from .models import MaliciousDomain,TestedURL

# Register your models here.
admin.site.register(MaliciousDomain)
admin.site.register(TestedURL)


