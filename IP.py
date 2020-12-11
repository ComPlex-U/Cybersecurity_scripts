from tkinter import *
from subprocess import PIPE, Popen
import os

class App:
    def __init__(self, master):
        frame = Frame(master)
        frame.grid()

        # create and position widgets

        self.label = Label(frame, text="Enter IP Address or Server Name:")
        self.label.grid(row=0, column=0, sticky=W)

        self.textbox = Text(frame, height=1, width=40)
        self.textbox.grid(row=1, column=0, columnspan=2, sticky=W)
        self.textbox.insert(END, "www.google.com")

        self.resultsBox = Text(frame, height=10, width=60)
        self.resultsBox.grid(row=3, column=0, columnspan=3, sticky=W)

        self.hi_there = Button(frame, text="Ping",
                               width=10, command=self.doPing)
        self.hi_there.grid(row=1, column=2, sticky=W)

    def doPing(self):
        # reset result box
        self.resultsBox.delete(1.0, END)
        # get text

        texttext = self.textbox.get(1.0, END)
        exelist = ['ping', '-n', '1']
        exelist.append(texttext)
        # Execute command (these ping commands are windows specific).
        # In Linux you would use the '-c' to specify count.

        exe = Popen(exelist, shell=False, stdout=PIPE, stderr=PIPE)
        out, err = exe.communicate()
        while out:
            self.resultsBox.insert(END, out)
            out, err = exe.communicate()

root = Tk()
app = App(root)
root.mainloop()

