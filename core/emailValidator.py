def work_email_validator(email):

    output = True

    excluded_domains = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'aol.com', 'icloud.com', 'mail.com', 'msn.com', 'live.com', 'yandex.com']

    domain = email.split('@')[1].lower()

    if domain in excluded_domains:

        output = "Please provide valid work email"
                
    return output

def check_work_email_for_other_users(email, emailPM):

    domainPM = emailPM.split('@')[1].lower()
    domain = email.split('@')[1].lower()
    output = None

    if domain == domainPM:

        output = True

    else:

        output = " As you are creating this person for your company, so this persons work email domain must be same as your work email domain "

    return output


