from django.db import models

# Create your models here.
class MaliciousDomain(models.Model):
    domain = models.CharField(max_length=500, unique=True)

    def __str__(self):
        return self.domain
    