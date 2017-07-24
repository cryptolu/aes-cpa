class AesTester:
    def __init__(self):
        self.key_schedule = None
        self.encryption = None
        self.key = None

    def test_key_schedule(self):
        self.key_schedule.run(self.key)

        for i in range(11):
            print('{:2}: '.format(i), end='')
            for j in range(16):
                print('{} '.format(format(self.key_schedule.round_keys[i][j], '02x')), end='')
            print()

    def test_encryption(self, plaintext, expected_ciphertext):
        self.key_schedule.run(self.key)

        self.encryption.set_round_keys(self.key_schedule.round_keys)
        ciphertext = self.encryption.encrypt(plaintext)

        print('ciphertext = {} '.format(format(ciphertext, '032x')), end='')
        if expected_ciphertext == ciphertext:
            print('OK!')
        else:
            print('WRONG!')

    def get_round_keys(self):
        self.key_schedule.run(self.key)

        for i in range(11):
            print('{:2}: '.format(i), end='')
            print('[ ', end='')
            for j in range(15):
                print('0x{}, '.format(format(self.key_schedule.round_keys[i][j], '02x')), end='')
            print('0x{} '.format(format(self.key_schedule.round_keys[i][15], '02x')), end='')
            print(']', end='')
            print()

    def run(self, key, plaintext, expected_ciphertext):
        self.key = key

        self.test_key_schedule()
        print()
        self.test_encryption(plaintext, expected_ciphertext)
        print()
        self.get_round_keys()
        print()

    def run_tests(self, tests):
        for key, plaintext, ciphertext in tests:
            self.run(key, plaintext, ciphertext)
            print()
