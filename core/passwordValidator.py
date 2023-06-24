from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _
import re

class ComplexPasswordValidator:
    """
    Validate whether the password contains minimum one uppercase, one digit and one symbol.
    """
    def validate(self, password, user=None):

        if re.search('[A-Z]', password)==None or re.search('[0-9]', password)==None or re.search('[^A-Za-z0-9]', password)==None or len(password) < 8:
            raise ValidationError(
                _("Password must contain 8 character which includes at least 1 number, 1 uppercase, and 1 non-alphanumeric character"),
                code='password_is_weak',
            )

    def get_help_text(self):
        return _("Password must contain 8 character which includes at least 1 number, 1 uppercase, and 1 non-alphanumeric character")
    

def ComplexPasswordValidatorFunc(password):

    if re.search('[A-Z]', password)==None or re.search('[0-9]', password)==None or re.search('[^A-Za-z0-9]', password)==None or len(password) < 8:

        return False
    
    else:

        return True