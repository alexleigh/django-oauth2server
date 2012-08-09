import time
from hashlib import sha512
from uuid import uuid4

class TimestampGenerator(object):
    """Callable Timestamp Generator that returns a UNIX time integer.

    **Kwargs:**

    * *seconds:* A integer indicating how many seconds in the future the
      timestamp should be. *Default 0*

    *Returns int*
    """
    def __init__(self, seconds=0):
        self.seconds = seconds

    def __call__(self):
        return int(time.time()) + self.seconds

class KeyGenerator(object):
    """Callable Key Generator that returns a random keystring.

    **Args:**

    * *length:* A integer indicating how long the key should be.

    *Returns str*
    """
    def __init__(self, length):
        self.length = length

    def __call__(self):
        return sha512(uuid4().hex).hexdigest()[0:self.length]