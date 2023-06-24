from Users_app.models import Users

def check_user_is_fullly_verified(user_obj):

    user_obj = Users.objects.get(id = user_obj.id)

    output = None

    if user_obj.is_email_verified == True and user_obj.is_phno_verified == True :

        output = True
    
    else:

        output = " Please Verify your Email and Phone no First "

    return output
    
def check_user_is_pm(pmobj):

    user_obj = Users.objects.get(id = pmobj.id)

    output = None

    if user_obj.user_role == "P" :


        output = True
    
    else:

        output = " Only Portfolio Manager Can perform this "

    return output