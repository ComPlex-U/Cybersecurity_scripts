import time
import threading
import logging
try:
    import tkinter as tk
    import tkinter.scrolledtext as ScrolledText
except ImportError:
    import Tkinter as tk
    import ScrolledText

class TextHandler(logging.Handler):
    
    def __init__(self, text):   
        logging.Handler.__init__(self)
        self.text = text

    def emit(self, record):
        msg = self.format(record)
        def append():
            self.text.configure(state='normal')
            self.text.insert(tk.END, msg + '\n')
            self.text.configure(state='disabled')
            self.text.yview(tk.END)
        self.text.after(0, append)

class myGUI(tk.Frame):
    def __init__(self, parent, *args, **kwargs):
        tk.Frame.__init__(self, parent, *args, **kwargs)
        self.root = parent
        self.build_gui()

    def build_gui(self):
        self.root.title('TEST')
        self.root.option_add('*tearOff', 'FALSE')
        self.grid(column=0, row=0, sticky='ew')
        self.grid_columnconfigure(0, weight=1, uniform='a')
        self.grid_columnconfigure(1, weight=1, uniform='a')
        self.grid_columnconfigure(2, weight=1, uniform='a')
        self.grid_columnconfigure(3, weight=1, uniform='a')
        st = ScrolledText.ScrolledText(self, state='disabled')
        st.configure(font='TkFixedFont')
        st.grid(column=0, row=1, sticky='w', columnspan=4)
        text_handler = TextHandler(st)


        logging.basicConfig(filename='syslog.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s')

        logger = logging.getLogger()
        logger.addHandler(text_handler)

def worker():
    while True:
        time.sleep(2)
        timeStr = time.asctime()
        msg = 'Current time: ' + timeStr
        logging.info(msg)

def main():

    root = tk.Tk()
    myGUI(root)

    t1 = threading.Thread(target=worker, args=[])
    t1.start()

    root.mainloop()
    t1.join()

main()