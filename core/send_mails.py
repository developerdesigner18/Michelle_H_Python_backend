from django.conf.global_settings import EMAIL_HOST_USER
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string

def send_mails(subject, text_body, html_body, email):

    try:

        # subject = render_to_string("message_subject.txt")
        # text_body = render_to_string("message_body.txt")
        # html_body = render_to_string("message_body.html")

        subject = subject
        text_body = text_body
        html_body = html_body

        msg = EmailMultiAlternatives(subject=subject, from_email=EMAIL_HOST_USER,
                                    to=[email], body=text_body)
        msg.attach_alternative(html_body, "text/html")
        msg.send()

        return True

    except:
        
        return False