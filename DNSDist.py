import base64
import socket
import logging
from struct import pack, unpack
try:
    import libnacl
    from libnacl.utils import rand_nonce
    from libnacl.secret import SecretBox
    HAVE_SODIUM = True
except ImportError:
    HAVE_SODIUM = False


class Console(object):
    def __init__(self, key=None, host='127.0.0.1', port=5199, have_sodium=HAVE_SODIUM):
        if have_sodium:
            if key:
                key = base64.b64decode(key)
            else:
                # libnacl won't like it if you send anything less then KEYBYTES
                key = '\0' * libnacl.crypto_secretbox_KEYBYTES
            self.__box = SecretBox(key=key)
            self.__my_nonce = rand_nonce()
        else:
            self.__box = None
            self.__my_nonce = '\0'
        self.__client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        logging.info('Connecting to %s:%d' % (host, port))
        self.__client.connect((host, port))
        logging.debug('Sending my nonce: %s' % self.__my_nonce.encode('hex'))
        self.__client.send(self.__my_nonce)
        if self.__box:
            self.__th_nonce = self.__client.recv(libnacl.crypto_secretbox_NONCEBYTES)
        else:
            self.__th_nonce = self.__client.recv(1)
        logging.debug('Got their nonce: %s' % self.__th_nonce.encode('hex'))

    @staticmethod
    def increment_nonce(nonce):
        count = unpack("!I", nonce[0:4])[0]
        count += 1
        return pack("!I", count) + nonce[4:]

    def _send(self, msg):
        self.__client.send(pack("!I", len(msg)))
        self.__client.send(msg)

    def _recvbits(self, bits):
        data = self.__client.recv(bits)
        while len(data) < bits:
            data += self.__client.recv(bits - len(data))
        return data

    def _recv(self):
        bits = self._recvbits(4)
        length = unpack("!I", bits)[0]
        logging.debug('Got length of %d' % length)
        return self._recvbits(length)

    def disconnect(self):
        self.__client.close()

    def execute(self, msg):
        logging.info("Sending: %s" % msg)
        if self.__box:
            msg = self.__box.encrypt(msg, nonce=self.__my_nonce, pack_nonce=False)[1]
            logging.info("Cipher text: %s" % msg.encode('hex'))
            self.__my_nonce = Console.increment_nonce(self.__my_nonce)
            logging.debug('New nonce: %s' % self.__my_nonce.encode('hex'))
        self._send(msg)

        logging.info("Waiting for response...")
        msg = self._recv()
        if self.__box:
            logging.info("Cipher text: %s" % msg.encode('hex'))
            msg = self.__box.decrypt(msg, nonce=self.__th_nonce)
            self.__th_nonce = Console.increment_nonce(self.__th_nonce)
            logging.debug('New nonce: %s' % self.__th_nonce.encode('hex'))
        logging.info("Received: %s" % msg)
        return msg
