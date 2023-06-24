from rest_framework_simplejwt.tokens import RefreshToken

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    refresh["user_role"] = user.user_role

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }