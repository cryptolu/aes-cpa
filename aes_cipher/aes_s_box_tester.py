from aes_cipher.key_schedule import KeySchedule
from aes_cipher.encryption_s_box import EncryptionSBox
from aes_cipher.aes_tester import AesTester


import time


class AesSBoxTester(AesTester):
    def __init__(self, key=None):
        super().__init__()
        self.key_schedule = KeySchedule()
        self.encryption = EncryptionSBox()
        self.key = key


def main():
    tester = AesSBoxTester()
    tests = [
        (0xf530357968578480b398a3c251cd1093, 0x00, 0xf5df39990fc688f1b07224cc03e86cea),
        (0x2b7e151628aed2a6abf7158809cf4f3c, 0x3243f6a8885a308d313198a2e0370734, 0x3925841d02dc09fbdc118597196a0b32)
    ]
    tester.run_tests(tests)


if "__main__" == __name__:
    start_time = time.time()

    main()

    stop_time = time.time()

    print('Duration: {}'.format(time.strftime('%H:%M:%S', time.gmtime(stop_time - start_time))))
