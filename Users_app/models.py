from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import MinLengthValidator
from .manager import UsersManager

# Create your models here.

USERS_ROLE = (

    ("I","Indivisual Investor"),
    ("P","Portfolio Manager"),
    ("C","Client"),
    ("F","Financial Analyst"),
    ("S","Stategist"),
    ("A","Admin"),

)

USERS_ACCOUNT_STATUS = (

    ("A","Activate"),
    ("D","Deactivate"),

)

USERS_STATUS = (

    ("O","Online"),
    ("OF","Offline"),

)



class Users(AbstractUser):

    username = models.CharField(max_length=20,unique=True)
    email = models.EmailField(unique=True)
    phone_no = models.CharField(max_length=10, validators=[MinLengthValidator(10)], unique=True)
    Date_of_birth = models.DateField(null=True, blank=True)
    state = models.CharField(max_length=50)
    city = models.CharField(max_length=50)
    area = models.CharField(max_length=50)
    image = models.ImageField(upload_to="", blank=True, null=True, default="", verbose_name="Image URL")
    
    is_email_verified = models.BooleanField(default=False, verbose_name="Email Verified")
    is_phno_verified = models.BooleanField(default=False, verbose_name="Phone No Verified")
    
    verification_otp_email = models.CharField(max_length=7, null=True, blank=True)
    verification_token_email = models.CharField(max_length=50, null=True, blank=True)
    verification_otp_phone = models.CharField(max_length=7, null=True, blank=True)

    user_role = models.CharField(max_length=10,choices=USERS_ROLE, null=True, blank=True)

    user_account_status = models.CharField(max_length=10,choices=USERS_ACCOUNT_STATUS, default="A")

    user_status = models.CharField(max_length=10,choices=USERS_STATUS, default="OF")

    user_created_by = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True)

    objects = UsersManager()

    REQUIRED_FIELDS = ['first_name', 'last_name','username']
    USERNAME_FIELD = 'email'

    class Meta:
        db_table = 'Users'


