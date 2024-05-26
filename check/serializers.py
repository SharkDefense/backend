from rest_framework import serializers
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError


class URLSerializer(serializers.Serializer):
    url = serializers.CharField()

    def validate_url(self, value):
        # Validate URL
        url_validator = URLValidator()
        try:
            url_validator(value)
        except ValidationError:
            raise serializers.ValidationError("Invalid URL")
        
        return value