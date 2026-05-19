from slowapi import Limiter
from slowapi.util import get_remote_address

# Identify clients by IP
limiter = Limiter(key_func=get_remote_address)
