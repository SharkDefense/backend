from django.db import models

# Create your models here.
class MaliciousDomain(models.Model):
    domain = models.CharField(max_length=500, unique=True)

    def __str__(self):
        return self.domain
    



class TestedURL(models.Model):
    url = models.CharField(max_length=2000, unique=True)
    state = models.CharField(max_length=100)
    count = models.PositiveIntegerField(default=1)

    def __str__(self):
        return self.url    