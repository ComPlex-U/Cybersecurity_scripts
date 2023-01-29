import csv
import sys
import subprocess
import time
import phonenumbers
from phonenumbers import geocoder
from phonenumbers import carrier


def main():
    menu()


def menu():
    print("************MENU**************")
    print()

    choice = input("""
                      A: Please Register
                      B: Port Scan
                      C: number
                      Q: Logout

                      Please enter your choice: """)

    if choice == "A" or choice == "a":
        register()
    elif choice == "B" or choice == "b":
        login()
    elif choice == "C" or choice == "c":
        IP()
    elif choice == "Q" or choice == "q":
        sys.exit
    else:
        print("You must only select either A or B")
        print("Please try again")
        menu()


def register():
    pass


def login():
    subprocess.call(["python", "fast_portscan.py"])
    time.sleep(2)
    main()

def IP():
    target = input('Enter the host to be scanned: ')
    phonne_number = phonenumbers.parse(target)

    print(target)
    print(geocoder.description_for_number(phonne_number, 'en'))
    print(carrier.name_for_number(phonne_number, 'en'))
    time.sleep(2)
    main()


main()