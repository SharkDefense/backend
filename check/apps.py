from django.apps import AppConfig


class CheckConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'check'
    def ready(self):
            from . import model_loader
            model_loader.initialize_model()