from aes_cipher.key_schedule import KeySchedule
from aes_cipher.encryption_s_box import EncryptionSBox


class Aes:
    def __init__(self, key):
        self.key = key

        self.key_schedule = KeySchedule()
        self.round_keys = self.key_schedule.run(self.key)

        self.encryption = EncryptionSBox(self.round_keys)

    def encrypt(self, plaintext):
        return self.encryption.encrypt(plaintext)
