# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import json


def main():
    certs = {'Certificates':
                {'Install':
                    ['/usr/local/share/ca-certificates/challenge-root-ca.crt']}}
    policies_path = '/usr/lib/firefox-esr/distribution/policies.json'

    with open(policies_path) as f:
        policies = json.load(f)

    policies['policies'].update(certs)

    with open(policies_path, 'w') as f:
        json.dump(policies, f, indent=2)


if __name__ == '__main__':
    main()
