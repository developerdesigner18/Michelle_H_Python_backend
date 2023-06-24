from django.contrib.auth.base_user import BaseUserManager

class UsersManager(BaseUserManager):

    use_in_migrations = True

    def create_user(self,email, password=None, **extra_fields):

        if not email:
            raise ValueError("Email Required")
        
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self,email, password, **extra_fields):

        extra_fields.setdefault('is_staff',True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('user_role',"A")
        extra_fields.setdefault('is_email_verified', True)
        extra_fields.setdefault('is_phno_verified', True)

        return self.create_user(email, password, **extra_fields)
       