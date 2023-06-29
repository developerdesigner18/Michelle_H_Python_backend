from rest_framework.response import Response
from . import serializers
from rest_framework.views import APIView
from rest_framework import status
from core.passwordValidator import ComplexPasswordValidatorFunc
from core.emailValidator import work_email_validator, check_work_email_for_other_users
from django.contrib.auth.hashers import make_password, check_password
from core.send_mails import send_mails
from core.tokens import get_tokens_for_user
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken
from rest_framework_simplejwt.authentication import JWTTokenUserAuthentication
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import login, logout
from .models import Users
from django.db.models import Q
from core.roles import check_user_is_fullly_verified, check_user_is_pm
from django.contrib.auth.tokens import default_token_generator
from core.otp import  send_email_otp, email_otp_verify
from rest_framework import mixins
from rest_framework import generics
from django.shortcuts import get_object_or_404
from core.password_generator import get_random_strong_password

# Create your views here.

class UsersRegistrationView(APIView):

    def post(self, request, format=None):

        serializer = serializers.UserRegistrationSerializer(data = request.data)

        if serializer.is_valid(raise_exception=True):

            if not ComplexPasswordValidatorFunc(request.data['password']):
                return Response({"error":"Password must contain 8 character which includes at least 1 number, 1 uppercase, and 1 non-alphanumeric character"}, status=status.HTTP_406_NOT_ACCEPTABLE)

            if request.data['user_role'] == 'I':

                user = serializer.save(password=make_password(request.data['password']))

                token = default_token_generator.make_token(user)
                user.verification_token_email = token
                user.save()
                verification_url = f'http://127.0.0.1:8000/users/verify-email/{token}/'

                subject = "Subject"
                text_body = "This is the body"
                html_body = f"<h1> Hello {request.data['first_name']} {request.data['last_name']} you have just registred successfully with {request.data['email']} email as a Indivisual Investor</h1><br><br> <p>{verification_url}</p>"

            elif request.data['user_role'] == 'P':

                check_work_email = work_email_validator(request.data['email'])

                if check_work_email == True:
                    
                    user = serializer.save(password=make_password(request.data['password']))

                    token = default_token_generator.make_token(user)
                    user.verification_token_email = token
                    user.save()
                    verification_url = f'http://127.0.0.1:8000/users/verify-email/{token}/'

                else:

                    return Response({"error": check_work_email}, status=status.HTTP_406_NOT_ACCEPTABLE)
                
                subject = "Subject"
                text_body = "This is the body"
                html_body = f"<h1> Hello {request.data['first_name']} {request.data['last_name']} you have just registred successfully with {request.data['email']} email as a Portfolio Manager</h1><br><br> <p>{verification_url}</p>"
                
            else:

                return Response({"error":"Only Indivisual Investor and Portfolio manager allow to Register their self"}, status=status.HTTP_406_NOT_ACCEPTABLE)

            user.user_created_by = user
            user.save()

            send_mail = send_mails(subject, text_body, html_body, request.data['email'])

            if send_mail == True:

                return Response({'success':'User Registred Successfully'},status=status.HTTP_201_CREATED ) 
            
            else:

                return Response({'success':'User Registred Successfully but mail not sent'},status=status.HTTP_201_CREATED )

class UsersLogOutView(APIView):

    authentication_classes = [JWTTokenUserAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):

        user_obj = Users.objects.get(id=request.user.id)

        tokens = OutstandingToken.objects.filter(user_id=request.user.id)

        logout(request)

        for token in tokens:
            t, _ = BlacklistedToken.objects.get_or_create(token=token)

        user_obj.user_status = "OF"
        user_obj.save()

        return Response({"success":"LogOut Succccessfully"},status=status.HTTP_200_OK)
    
class UsersLoginView(APIView):

    def post(self, request, format=None):
        
        serializer = serializers.UsersLoginSerializer(data=request.data)

        if serializer.is_valid(raise_exception=True):

            username = serializer.data.get('username')
            password = serializer.data.get('password')

            try:
                users_obj = Users.objects.get(
                    Q(username=username) | Q(email=username) | Q(phone_no=username)
                )
                role = users_obj.user_role
            except:
                users_obj = None
                return Response({'error':'Username Invalid'}, status=status.HTTP_401_UNAUTHORIZED)
                
            if users_obj != None:

                if check_password(password, users_obj.password):

                    if users_obj.user_account_status == "A":

                        login(request, users_obj)

                        users_obj.user_status = "O"
                        users_obj.save()

                        token = get_tokens_for_user(users_obj)

                        return Response({'token':token,'Success':'login Success'},status=status.HTTP_200_OK) 

                    else:

                        return Response({'error':'Your account is not active, please contact to Admin.'})
                                
                else:
                    return Response({'error':'Invalid Password'}, status=status.HTTP_401_UNAUTHORIZED)

            else:
                
                return Response({'error':'Invalid Username'}, status=status.HTTP_400_BAD_REQUEST)
            
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)

class UserCreationByPMView(APIView):

    authentication_classes = [JWTTokenUserAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):

        requested_user = Users.objects.get(id = request.user.id)
        check_user_role = check_user_is_pm(request.user)

        if check_user_role == True:

            user_verification = check_user_is_fullly_verified(request.user)

            if user_verification == True:

                print(request.data)

                if "password" in  request.data:
                    return Response({'error':'Do not password for crearting user, we will generate random password and send user via email'})
                
                serializer = serializers.UserRegistrByPMSerializer(data = request.data)

                if serializer.is_valid(raise_exception=True):

                    # if not ComplexPasswordValidatorFunc(request.data['password']):
                    #     return Response({"error":"Password must contain 8 character which includes at least 1 number, 1 uppercase, and 1 non-alphanumeric character"}, status=status.HTTP_406_NOT_ACCEPTABLE)

                    user_roles = [ 'C', 'F', 'S' ]

                    if request.data['user_role'].upper() not in user_roles:
                        return Response(
                            {"error": "Portfolio Manager can creatre Clients, Financial Analyst and Stategist"},
                            status=status.HTTP_406_NOT_ACCEPTABLE)

                    if request.data['user_role'].upper() == 'C':

                        pass

                    else:

                        check_work_email = work_email_validator(request.data['email'])

                        if check_work_email == True:

                            check_work_email_of_users = check_work_email_for_other_users(requested_user.email, request.data['email'])

                            if check_work_email_of_users == True:

                                pass

                            else:

                                return Response({"error": check_work_email_of_users}, status=status.HTTP_406_NOT_ACCEPTABLE)

                        else:

                            return Response({"error": check_work_email}, status=status.HTTP_406_NOT_ACCEPTABLE)

                    u_username = request.data['username']
                    u_password = get_random_strong_password()

                    user = serializer.save(password=make_password(u_password))
                    user.user_created_by = requested_user
                    user.save()

                    token = default_token_generator.make_token(user)
                    user.verification_token_email = token
                    user.save()

                    verification_url = f'http://127.0.0.1:8000/users/verify-email/{token}/'

                    if request.data['user_role'] == 'C':

                        subject = "Subject"
                        text_body = "This is the body"
                        html_body = f"<h1> Hello {request.data['first_name']} {request.data['last_name']} you have just registred successfully with {request.data['email']} email as a Client</h1><br><br> <p>{verification_url}</p><br><br><p>Username : {u_username}</p><br><br><p>Password : {u_password}</p>"

                    elif request.data['user_role'] == 'F':

                        subject = "Subject"
                        text_body = "This is the body"
                        html_body = f"<h1> Hello {request.data['first_name']} {request.data['last_name']} you have just registred successfully with {request.data['email']} email as a Financial Analyst</h1><br><br> <p>{verification_url}</p><br><br><p>Username : {u_username}</p><br><br><p>Password : {u_password}</p>"

                    elif request.data['user_role'] == 'S':

                        subject = "Subject"
                        text_body = "This is the body"
                        html_body = f"<h1> Hello {request.data['first_name']} {request.data['last_name']} you have just registred successfully with {request.data['email']} email as a Stategist</h1><br><br> <p>{verification_url}</p><br><br><p>Username : {u_username}</p><br><br><p>Password : {u_password}</p>"
                        
                    else:

                        return Response({"error":"Portfolio Manager can creatre Clients, Financial Analyst and Stategist"}, status=status.HTTP_406_NOT_ACCEPTABLE)

                    send_mail = send_mails(subject, text_body, html_body, request.data['email'])

                    if send_mail == True:

                        return Response({'success':'User Registred Successfully'},status=status.HTTP_201_CREATED ) 
                    
                    else:

                        return Response({'success':'User Registred Successfully but mail not sent'},status=status.HTTP_201_CREATED )
                
                else:

                    return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
                
            else:

                return Response({'error':user_verification}, status=status.HTTP_401_UNAUTHORIZED)
        
        else:

            return Response({'error': check_user_role }, status=status.HTTP_401_UNAUTHORIZED)

class UserEmailVerificationView(APIView):

    def get(self, request, token):

        request_user = Users.objects.get(verification_token_email=token)

        if request_user.is_email_verified == True:

            return Response({'error':'Your Email is already verified'}, status= status.HTTP_400_BAD_REQUEST)

        else:

            if request_user.verification_token_email == token:

                request_user.is_email_verified = True
                request_user.save()
                return Response({'success':'Email Verified Successfully'},status=status.HTTP_200_OK)

            else:

                return Response({'error':'Bad URL Request'}, status= status.HTTP_404_NOT_FOUND)


class UsersForgotPasswordView(APIView):

    def post(self, request, format=None):

        serializer = serializers.UserForgotPasswordSerializer(data=request.data)

        if serializer.is_valid(raise_exception=True):

            username = serializer.data.get('username')

            try:
                users_obj = Users.objects.get(
                    Q(username=username) | Q(email=username) | Q(phone_no=username)
                )
            except:
                users_obj = None
                return Response({'error': 'User Detail Invalid'}, status=status.HTTP_404_NOT_FOUND)

            if users_obj != None:

                otp_send = send_email_otp(users_obj.email, "FP")

                if otp_send == 'Success':

                    return Response({'Success': 'Otp sent successfully'}, status=status.HTTP_200_OK)

                else:

                    return Response({'error': 'Otp not sent'}, status=status.HTTP_403_FORBIDDEN)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class UserForgotPasswordOTPVerifyView(APIView):

    def post(self, request, format=None):

        if not 'otp' in request.data:

            return Response({'error':'OTP Required'}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = serializers.UserForgotPasswordSerializer(data=request.data)

        if serializer.is_valid(raise_exception=True):

            username = serializer.data.get('username')
            otp = request.data.get('otp')

            print(otp)
            print(type(otp))

            try:

                users_obj = Users.objects.get(
                    Q(username=username) | Q(email=username) | Q(phone_no=username)
                )

                user_email = users_obj.email

                Verify_OTP = email_otp_verify(user_email, otp, "FP")

                if Verify_OTP == "Success":

                    return Response({'success':'OTP verified successfully'},status=status.HTTP_200_OK)
                
                else:
                    
                    return Response({'error':'Invalid OTP'},status=status.HTTP_404_NOT_FOUND)

            except:

                return Response({'error':'User Detail Invalid'},status=status.HTTP_404_NOT_FOUND)
            
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
    
class UserForgotPasswordChangeView(APIView):

    def post(self, request, format=None):
        
        serializer = serializers.UserForgotPasswordChangeSerializer(data=request.data)

        if serializer.is_valid(raise_exception=True):

            username = serializer.data.get('username')
            password = serializer.data.get('password')

            if not ComplexPasswordValidatorFunc(password):
                return Response({"erro":"Password must contain 8 character which includes at least 1 number, 1 uppercase, and 1 non-alphanumeric character"}, status=status.HTTP_406_NOT_ACCEPTABLE)

            try:
                users_obj = Users.objects.get(
                    Q(username=username) | Q(email=username) | Q(phone_no=username)
                )
            except:
                users_obj = None
                return Response({'error':'Invalid Username'}, status=status.HTTP_401_UNAUTHORIZED)

            if users_obj != None:

                if users_obj.password == password or check_password(password,users_obj.password):

                    return Response({"error":"New password is as same as Old password"},status=status.HTTP_406_NOT_ACCEPTABLE)
                
                else:

                    users_obj.password = make_password(password)
                    users_obj.save()

                    return Response({"Success":"Password Changed Successfully"},status=status.HTTP_200_OK)
                
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
    
class UsersEmailVerifySendOTP(APIView):

    authentication_classes = [JWTTokenUserAuthentication,]
    permission_classes = (IsAuthenticated,)
    
    def post(self, request, format=None):

        try:
            users_obj = Users.objects.get(id=request.user.id)
        except:
            users_obj = None
            return Response({'error':'User Email Invalid'},status=status.HTTP_404_NOT_FOUND)

        if users_obj != None:

            if users_obj.is_email_verified == True:
                return Response({"error":"Email already verified"}, status=status.HTTP_406_NOT_ACCEPTABLE)

            otp_send = send_email_otp(users_obj.email, "EV")

            if otp_send == 'Success':

                return Response({'Success':'Otp sent successfully'},status=status.HTTP_200_OK)

            else:

                return Response({'message':'Otp not sent'},status=status.HTTP_403_FORBIDDEN)
            
class UsersEmailVerifyOTPVerifyView(APIView):

    authentication_classes = [JWTTokenUserAuthentication,]
    permission_classes = (IsAuthenticated,)

    def post(self, request, format=None):

        if not 'otp' in request.data:

            return Response({'error':'OTP Required'}, status=status.HTTP_404_NOT_FOUND)
        
        otp = request.data.get('otp')

        try:

            users_obj = Users.objects.get(id=request.user.id)

            Verify_OTP = email_otp_verify(users_obj.email, otp, "EV")

            if Verify_OTP == "Success":

                return Response({'success':'OTP verified successfully'},status=status.HTTP_200_OK)
            
            else:
                
                return Response({'error':'Invalid OTP'},status=status.HTTP_404_NOT_FOUND)

        except:

            return Response({'error':'User Email Invalid'},status=status.HTTP_404_NOT_FOUND)
        
class UsersDetailsUpdateView(generics.GenericAPIView,mixins.UpdateModelMixin):

    authentication_classes = [JWTTokenUserAuthentication,]
    permission_classes = (IsAuthenticated,)

    queryset = Users.objects.all()
    serializer_class = serializers.UsersUpdateSerializer

    def patch(self, request):

        id = request.user.id
        users_obj = Users.objects.get( id = id )

        if "email" in request.data:

            email_exists = Users.objects.filter(email=request.data["email"]).exists()

            if email_exists:
                return Response({"error":"User with this Email already exists"},status=status.HTTP_406_NOT_ACCEPTABLE)

            users_obj.is_email_verified = False
            users_obj.save()
        
        if "phone_no" in request.data:

            phone_np_exists = Users.objects.filter(phone_no=request.data["phone_no"]).exists()

            if phone_np_exists:
                return Response({"error":"User with this Phone_no already exists"},status=status.HTTP_406_NOT_ACCEPTABLE)

            users_obj.is_phno_verified = False
            users_obj.save()

        return self.partial_update(request, id)
    
    def get_object(self):

        queryset = self.get_queryset()
        obj = get_object_or_404(queryset, id=self.request.user.id)
        return obj
    
class UserDetailView(generics.RetrieveAPIView, mixins.RetrieveModelMixin):

    authentication_classes = [JWTTokenUserAuthentication,]
    permission_classes = (IsAuthenticated,)

    queryset = Users.objects.all()
    serializer_class = serializers.UserAllDetailsSerializer

    def get(self, request, *args, **kwargs):

        return self.retrieve(request, *args, **kwargs)
    
    def get_object(self):

        queryset = self.get_queryset()
        obj = get_object_or_404(queryset, id=self.request.user.id)
        return obj

class UsersDeleteview(generics.GenericAPIView,mixins.DestroyModelMixin):

    authentication_classes = [JWTTokenUserAuthentication,]
    permission_classes = (IsAuthenticated,)

    queryset = Users.objects.all()

    def delete(self, request):
        
        return self.destroy (request)
    
    def get_object(self):

        queryset = self.get_queryset()
        obj = get_object_or_404(queryset, id=self.request.user.id)
        return obj
        