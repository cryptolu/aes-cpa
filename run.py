from cpa_attacker.attacker import Attacker


import os
import time


def main():
    os.chdir('./cpa_attacker/')

    attacker = Attacker(generate_traces=True, t_tables_implementation=True, debug=False)
    attacker.attack_guessing_entropy_evaluation_cases()


if "__main__" == __name__:
    start_time = time.time()

    main()

    stop_time = time.time()

    print('Duration: {}'.format(time.strftime('%H:%M:%S', time.gmtime(stop_time - start_time))))
