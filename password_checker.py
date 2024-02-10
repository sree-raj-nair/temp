import hashlib

import requests

import sys


def request_api(query):
    url = "https://api.pwnedpasswords.com/range/" + query
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f"Error fetching {res.status_code}, check api again")
    return res


def get_password_leaks_counts(hashes, hash_to_check):
    hashes = (line.split(":") for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_password(password):
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first_5, tail = sha1_password[:5], sha1_password[5:]
    response = request_api(first_5)
    return get_password_leaks_counts(response, tail)


def main(args):
    for password in args:
        count = pwned_password(password)
        if count:
            print(f"The {password} has been found {count} times. Please change the password ASAP.")
        else:
            print(f"The {password} was not found. Carry ON!!!!!")
    return 'done'


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
