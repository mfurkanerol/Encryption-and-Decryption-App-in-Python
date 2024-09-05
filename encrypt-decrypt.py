import tkinter
from tkinter import *
from PIL import Image, ImageTk
from tkinter import messagebox
from cryptography.fernet import Fernet
import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

#deriving the key
def derive_key(password, salt):
    password = password.encode()  #convert password to bytes
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

#encryption
def encrypt_text():
    title = titleEntry.get()
    message = textText.get("1.0", tkinter.END).strip()
    master_key = masterKeyEntry.get()

    #is there any empty blank
    if not title or not message or not master_key:
        messagebox.showerror("ERROR", "Please fill all the blanks.")
        return

    #creating salt
    salt = os.urandom(16)
    key = derive_key(master_key, salt)
    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(message.encode())

    #saving salt and encrypted message in encrypted_notes.txt with UTF-8 encoding
    with open("encrypted_notes.txt", "a", encoding="utf-8") as file:
        file.write(f"Başlık: {title}\n")
        file.write(f"Salt: {base64.urlsafe_b64encode(salt).decode()}\n")
        file.write(f"Encrypted Message: {encrypted_message.decode()}\n")
        file.write(f"---\n")  # Her başlık arasında ayırıcı olarak

    messagebox.showinfo("SUCCESSFUL", "The text is successfully encrypted.")
    clear_everything()

#decryption
def decrypt_text():
    title = titleEntry.get()
    master_key = masterKeyEntry.get()

    #is there any empty blank
    if not title or not master_key:
        messagebox.showerror("ERROR", "Please write the title and the master key.")
        return

    try:
        with open("encrypted_notes.txt", "r", encoding="utf-8") as file:
            lines = file.readlines()
            for i in range(0, len(lines), 4):  #we assume that each record has 4 lines
                if lines[i].strip() == f"Başlık: {title}":
                    salt = base64.urlsafe_b64decode(lines[i + 1].split(": ")[1].strip())
                    encryptedMessage = lines[i + 2].split(": ")[1].strip()

                    key = derive_key(master_key, salt)
                    fernet = Fernet(key)

                    try:
                        decryptedMessage = fernet.decrypt(encryptedMessage.encode()).decode()
                        #we show the encrypted message in the text box
                        textText.delete("1.0", tkinter.END)  #delete existing text
                        textText.insert(tkinter.END, decryptedMessage)  #show decrypted text
                        return
                    except:
                        messagebox.showerror("ERROR", "Decryption failed. The master key may be wrong.")
                        return
            messagebox.showerror("ERROR", "There is no such a title.")
    except Exception as e:
        messagebox.showerror("ERROR", f"An error is occurred while reading the file: {str(e)}")

#clearing every blank
def clear_everything():
    titleEntry.delete(0,END)
    textText.delete('1.0',END)
    masterKeyEntry.delete(0,END)

#creating the window/root/screen
window = tkinter.Tk()
window.config(pady=15)
window.title("Secret Note")
window.minsize(400,690)
window.maxsize(400,690)

#we upload the PNG file and resize it
image = Image.open("C:/Users/mfurk/Downloads/2255350.png")
resizedImage = image.resize((100, 100))

#to make it compatible with Tkinter, we use ImageTk
img = ImageTk.PhotoImage(resizedImage)

#we put the image in a label
imageLabel = tkinter.Label(window, image=img)

#we create label&text for the title
titleLabel = tkinter.Label(text="Enter your title:",font=("Arial",11,"bold"),fg="#1a6fb0")
titleEntry = tkinter.Entry(width=25,font=("Arial", 10, "normal"))

#we create label&text for the text box
textLabel = tkinter.Label(text="Enter your text:",font=("Arial",11,"bold"),fg="#1a6fb0")
textText = tkinter.Text(width=45,height=16,font=("Arial",10,"normal"))

#we create label&text for the master key
masterKeyLabel = tkinter.Label(text="Enter the Master Key:",font=("Arial",11,"bold"),fg="#1a6fb0")
masterKeyEntry = tkinter.Entry(width=45,font=("Arial",10,"normal"))

#we create button for encryption
encryptionButton = tkinter.Button(text="Encrypt & Save",command=encrypt_text)

#we create button for decryption
decryptionButton = tkinter.Button(text="Decrypt",command=decrypt_text)

#we create button for 'clear'
clearButton = tkinter.Button(text="Clear",command=clear_everything)

#created by Furkan Erol
furkanLabel = tkinter.Label(text="Created by Furkan Erol",font=("Arial",8,"normal"),fg="dark gray")

#we order everything
imageLabel.pack(pady=15)
titleLabel.pack(pady=3)
titleEntry.pack(pady=3)
textLabel.pack(pady=3)
textText.pack(pady=3)
masterKeyLabel.pack(pady=3)
masterKeyEntry.pack(pady=3)
encryptionButton.pack(pady=3)
decryptionButton.pack(pady=3)
clearButton.pack(pady=3)
furkanLabel.place(x=15,y=0)

window.mainloop()