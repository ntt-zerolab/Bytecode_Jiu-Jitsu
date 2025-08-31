import json
import sys

def load_config(config_file):
    try:
        with open(config_file, 'r') as f:
            config_string = f.read()
    except FileNotFoundError:
        print('Error: No such file {}'.format(config_file))
        return None

    try:
        config = json.loads(config_string)
    except json.JSONDecodeError:
        print('Error: could not decode JSON string {}'.format(config_string))
        return None
    except Exception as e:
        print('Error: unknown error {}'.format(e))
        return None

    return config


def is_config_valid(config):
    if 'characteristic_values' not in config.keys():
        return False
    return True