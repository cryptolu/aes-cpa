import configparser
import os


class ActiveSettings:
    instance = None

    def __new__(cls, *args, **kwargs):
        if not cls.instance:
            cls.instance = super(ActiveSettings, cls).__new__(cls, *args, **kwargs)

            cls.instance.key = 0x00
            cls.instance.random_state = [0] * 16

            working_dir = os.getcwd()
            package_dir = os.path.dirname(os.path.dirname(__file__))
            configuration_file = os.path.join(os.path.relpath(package_dir, working_dir), 'settings/settings.ini')

            try:
                config_parser = configparser.ConfigParser()
                config_parser.read(configuration_file)

                key = config_parser.get('AES', 'key')
                cls.instance.key = int(key, 16)

                random_state = config_parser.get('AES', 'random_state')
                cls.instance.random_state = list(map(lambda it: int(it.strip('[ ]'), 16), random_state.split(',')))
            except Exception as e:
                print('ERROR in {}: {}!'.format(cls.instance.__class__.__name__, e))

        return cls.instance


def main():
    active_settings = ActiveSettings()
    print('Active settings')
    print('-' * 15)

    print('key              0x{}'.format(format(active_settings.key, '032x')))

    print('random_state     [', end='')
    length = len(active_settings.random_state) - 1
    for i in range(length):
        print('0x{}, '.format(format(active_settings.random_state[i], '02x')), end='')
    print('0x{}] '.format(format(active_settings.random_state[length], '02x')), end='')


if "__main__" == __name__:
    main()
