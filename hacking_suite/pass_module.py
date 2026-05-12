import random
import string

def generar_contrasena(longitud):
    if longitud < 8:
        raise ValueError("Mínimo 8 caracteres")
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(longitud))