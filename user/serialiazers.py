from rest_framework import serializers
from .models import User


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'name', 'password', 'twitter', 'facebook', 'linkedin', 'instagram', 'website',
                  'profile_picture', 'is_staff', 'is_active']
        extra_kwargs = {
            'password': {'write_only': True},
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.context.get('update', False):
            for field_name, field in self.fields.items():
                # if field_name != 'email':
                field.required = False

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance

    def update(self, instance, validated_data):
        email = validated_data.get('email', None)
        if email:
            validated_data.pop('email')
        for attr, value in validated_data.items():
            if attr == 'password':
                instance.set_password(value)
            else:
                setattr(instance, attr, value)
        instance.save()
        return instance
