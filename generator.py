import secrets, string

class PasswordGenerator:
    @staticmethod
    def generate(length: int = 16, use_symbols: bool = True) -> str:
        if length < 6:
            raise ValueError('Minimum length is 6')
        alphabet = string.ascii_letters + string.digits
        if use_symbols:
            alphabet += '!@#$%^&*()-_=+[]{};:,.<>/?'
        return ''.join(secrets.choice(alphabet) for _ in range(length))
