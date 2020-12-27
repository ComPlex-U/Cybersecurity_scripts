import csv
import sys
import subprocess
import time


def main():
    menu()


def menu():
    print("************MENU**************")
    print()

    choice = input("""
                      A: Please Register
                      B: teste
                      Q: Logout

                      Please enter your choice: """)

    if choice == "A" or choice == "a":
        register()
    elif choice == "B" or choice == "b":
        login()
    elif choice == "Q" or choice == "q":
        sys.exit
    else:
        print("You must only select either A or B")
        print("Please try again")
        menu()


def register():
    pass


def login():
    subprocess.call(["python", "teste.py"])
    time.sleep(2)
    main()


main()