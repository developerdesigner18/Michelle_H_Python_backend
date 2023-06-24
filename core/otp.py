from Users_app.models import Users
from core.send_mails import send_mails
from random import randint
        
def email_otp_verify(email, otp, for_what):
                
    users_obj = Users.objects.get(email=email) 
        
    otp_from_database = users_obj.verification_otp_email

    if int(otp_from_database) == int(otp):

        if for_what == "FP":
            
            users_obj.verification_otp_email = ""
            users_obj.save()

            return "Success"

        elif for_what == "EV":

            users_obj.is_email_verified = True
            users_obj.verification_otp_email = ""
            users_obj.save()

            return "Success"
        
        else:

            return "Failed"

    else:

        return "Failed"


def send_email_otp(email, for_what):

    try:
        users_obj = Users.objects.get(email=email)
        role = users_obj.user_role
    except:
        pass
            
    try:
        
        otp = randint(100001, 999999)
        users_obj.verification_otp_email = otp
        users_obj.save()

        if for_what == "FP" and role == "I":

            subject = "Subject"
            text_body = "This is the body"
            html_body = f"<h1>This Is OTP{otp} for forgot password User</h1>"

        elif for_what == "EV" and role == "I":

            subject = "Subject"
            text_body = "This is the body"
            html_body = f"<h1>This Is OTP{otp} for email verify User</h1>"

        elif for_what == "FP" and role == "P":

            subject = "Subject"
            text_body = "This is the body"
            html_body = f"<h1>This Is OTP{otp} for forgot password Staff</h1>"

        elif for_what == "EV" and role == "P":

            subject = "Subject"
            text_body = "This is the body"
            html_body = f"<h1>This Is OTP{otp} for email verify Staff</h1>"

        elif for_what == "FP" and role == "C":

            subject = "Subject"
            text_body = "This is the body"
            html_body = f"<h1>This Is OTP{otp} for forgot password Admin</h1>"

        elif for_what == "EV" and role == "C":

            subject = "Subject"
            text_body = "This is the body"
            html_body = f"<h1>This Is OTP{otp} for email verify Admin</h1>"

        elif for_what == "FP" and role == "F":

            subject = "Subject"
            text_body = "This is the body"
            html_body = f"<h1>This Is OTP{otp} for forgot password Admin</h1>"

        elif for_what == "EV" and role == "F":

            subject = "Subject"
            text_body = "This is the body"
            html_body = f"<h1>This Is OTP{otp} for email verify Admin</h1>"

        elif for_what == "FP" and role == "S":

            subject = "Subject"
            text_body = "This is the body"
            html_body = f"<h1>This Is OTP{otp} for forgot password Admin</h1>"

        elif for_what == "EV" and role == "S":

            subject = "Subject"
            text_body = "This is the body"
            html_body = f"<h1>This Is OTP{otp} for email verify Admin</h1>"

        send_mail = send_mails(subject, text_body, html_body, email)

        if send_mail == True:

            return 'Success'
        
        else:

            return 'Failed'

    except:

        return 'Failed'
