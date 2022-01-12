
# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from collections.abc import Callable
import requests

# Update for open-sourcing
# SERVER = "http://10.5.5.5"
SERVER = "http://localhost:8000"
FIRST = "/".join((SERVER, "first"))
SECOND = "/".join((SERVER, "second"))
THIRD = "/".join((SERVER, "third"))


def interact(url: str, element_type: Callable):
    """Interact with the server.

    :param url: Server URL.
    :type url: str
    :param element_type: One of the built-in primitive types, should be str or int.
    :type element_type: Callable
    """
    try:
        resp = requests.get(url)
    except requests.exceptions.ConnectionError:
        print(
            "Could not reach the server. Please report this error to President's Cup support."
        )
        return
    else:
        data = resp.json()
        print(data["sequence"])
    while True:
        out = input(
            f"The server is asking for another {data['resp_len']}"
            " item(s) to complete the above sequence (separate with spaces, r to return):\n"
        )
        if out == 'r':
            return
        try:
            submission = list(map(element_type, out.split()))
        except Exception:
            print(
                "Could not parse your response into a list of "
                f"{element_type.__name__} values - please try again."
            )
            continue
        if len(submission) != int(data["resp_len"]):
            print(
                "Your response is not the right length for the requested token."
                f" You entered {len(submission)} elements, but the server was"
                f" expecting {int(data['resp_len'])}"
            )
            continue
        resp = requests.post(url, json={"sequence": submission})
        print(resp.content)
        return



def first():
    interact(FIRST, int)


def second():
    interact(SECOND, str)


def third():
    interact(THIRD, int)


def outer_menu():
    choices = {"1": first, "2": second, "3": third, "q": quit}
    while True:
        choice = input(
            "Which part do you want to attempt? (1, 2, 3, or q to stop)\n"
        ).strip()
        try:
            choices[choice]()
        except KeyError:
            print(f"Could not parse your choice, which was {choice}")
            continue


def main():
    outer_menu()


if __name__ == "__main__":
    main()

