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
