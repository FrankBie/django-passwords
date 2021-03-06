from django.forms import CharField, PasswordInput

from passwords.validators import validate_length, common_sequences
from passwords.validators import dictionary_words, complexity
from passwords.validators import common_sub_string


class PasswordField(CharField):
    default_validators = [validate_length, common_sequences, 
                          dictionary_words, complexity, 
                          common_sub_string]


    def __init__(self, *args, **kwargs):
        if not kwargs.has_key("widget"):
            kwargs["widget"] = PasswordInput(render_value=False)
        
        super(PasswordField, self).__init__(*args, **kwargs)