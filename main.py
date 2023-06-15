from tkinter import *
from tkinter import Label
from tkinter import ttk
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from xorencryption import XOREncryption
import pyDes



root = Tk()
root.title("Encryption Tool")
root.geometry("800x600")


def BtnEn():
    clear_text = txt1.get(1.0, END)
    key = txt1K.get(1.0, END)
    lb1R.delete(1.0, END)

    if list.get() == "XOR":
        global convert

        enc = XOREncryption()
        enc.set_plaintext(plaintext=clear_text)
        enc.set_key(key=key)
        convert = enc.encrypt()
        lb1R.insert(END, convert)

    elif list.get() == "Shift":

        result = ""
        s = int(key)
        for i in range(len(clear_text)):
            char = clear_text[i]
            if char == ' ':
                result += ' '
            else:
                if char.isupper():
                    result += chr((ord(char) + s - 65) % 26 + 65)
                else:
                    result += chr((ord(char) + s - 97) % 26 + 97)
        convert = result
        lb1R.insert(END, convert[:-1])

    elif list.get() == "AES":
        global key1
        global nonce
        global convert_b
        global ciphertext

        cipher = AES.new(key1, AES.MODE_EAX)
        data = clear_text.encode()
        nonce = cipher.nonce
        ciphertext = cipher.encrypt(data)
        cipher_str = str(ciphertext)
        convert_b = ciphertext
        lb1R.insert(END, cipher_str)

    elif list.get() == "DES":
        global ciphertext2
        global key2
        global k
        global convert_b2

        data = clear_text.encode()
        k = pyDes.des(key2, pyDes.CBC, "\0\0\0\0\0\0\0\0", pad=None, padmode=pyDes.PAD_PKCS5)
        ciphertext2 = k.encrypt(data)
        cipher_str = str(ciphertext2)
        convert_b2 = ciphertext2
        lb1R.insert(END, cipher_str)


def BtnDe():
    cipher = txt2.get(1.0, END)
    key = txt2K.get(1.0, END)
    lb2R.delete(1.0, END)

    if list.get() == "XOR":
        enc = XOREncryption()
        enc.set_plaintext(plaintext=cipher)
        enc.set_key(key=key)
        m = enc.encrypt()[:-1]
        lb2R.insert(END, m)

    elif list.get() == "AES":
        global ciphertext

        cipher1 = AES.new(key1, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher1.decrypt(ciphertext)
        lb2R.insert(END, str(plaintext)[2:-3])

    elif list.get() == "DES":
        global ciphertext2
        global key2
        global k

        k = pyDes.des(key2, pyDes.CBC, "\0\0\0\0\0\0\0\0", pad=None, padmode=pyDes.PAD_PKCS5)
        plaintext = k.decrypt(ciphertext2)
        lb2R.insert(END, plaintext)

    elif list.get() == "Shift":

        result = ""
        s = int(key)
        for i in range(len(cipher)):
            char = cipher[i]
            if char == ' ':
                result += ' '
            else:
                if char.isupper():
                    result += chr((ord(char) - s - 65) % 26 + 65)
                else:
                    result += chr((ord(char) - s - 97) % 26 + 97)
        lb2R.insert(END, result[:-1])



def gene():
    global key1
    global key2

    txt2K.delete(1.0, END)
    txt1K.delete(1.0, END)
    if list.get() == "AES":
        key1 = get_random_bytes(16)
        txt2K.insert(END, str(key1))
        txt1K.insert(END, str(key1))
    elif list.get() == "DES":
        key2 = get_random_bytes(8)
        txt2K.insert(END, str(key2))
        txt1K.insert(END, str(key2))
    else:
        txt2K.insert(END, "generation is for\n'AES' or 'DES'")
        txt1K.insert(END, "generation is for\n'AES' or 'DES'")


def clear():

    txt1.delete(1.0, END)
    lb1R.delete(1.0, END)
    txt1K.delete(1.0, END)
    txt2.delete(1.0, END)
    lb2R.delete(1.0, END)
    txt2K.delete(1.0, END)

typesEn = [
    "Shift",
    "XOR",
    "DES",
    "AES"
]

lbC = Label(root, text="Choose The Algorithm", font="20")
lbC.pack()

list = ttk.Combobox(root, values=typesEn, font="20")
list.current(0)
list.pack()

lblFr1 = LabelFrame(root, text="Encryption", font="8")
lblFr1.pack(expand="yes", fill="both")

lblFr2 = LabelFrame(root, text="Decryption", font="8")
lblFr2.pack(expand="yes", fill="both")

lblFr3 = LabelFrame(root, text="Key Generation", font="8")
lblFr3.pack(expand="yes", fill="both")

lb1T = Label(lblFr1, text="Enter The Plain Text", font="20")
lb1T.pack()
txt1 = Text(lblFr1, width="60", height="2")
txt1.pack()
lb1K = Label(lblFr1, text="Enter The Key", font="20")
lb1K.pack()
txt1K = Text(lblFr1, width="30", height="2")
txt1K.pack()
btnEn = Button(lblFr1, command=BtnEn, text="Encrypt", width="10", font="20", bg="red")
btnEn.pack()
lb1R = Text(lblFr1, width=50, height=2, font=("Helvetica", 20))
lb1R.pack()
#lb1R: Label = Label(lblFr1, text="Cipher Text Will Be Here ;)", font="20")
#lb1R.pack()

lbSpace = Label(root, text="", font="20")
lbSpace.pack()
lb2T = Label(lblFr2, text="Enter The Cipher Text", font="20")
lb2T.pack()
txt2 = Text(lblFr2, width="60", height="2")
txt2.pack()
lb2K = Label(lblFr2, text="Enter The Key", font="20")
lb2K.pack()
txt2K = Text(lblFr2, width="30", height="2")
txt2K.pack()
btnDe = Button(lblFr2, command=BtnDe, text="Decrypt", width="10", font="20", bg="green")
btnDe.pack()
lb2R = Text(lblFr2, width=50, height=2, font=("Helvetica", 20))
lb2R.pack()
#lb2R = Label(lblFr2, text="Plain Text Will Be Here ;)", font="20")
#lb2R.pack()

b4 = Button(root, command=gene, text="Generate key", width="10", font="20", bg="orange")
b4.pack()

b5 = Button(root, command=clear, text="Reset", width="10", font="20", bg="orange")
b5.pack()

b4.place(relx=0.7, rely=0.02)
b5.place(relx=0.1, rely=0.02)

root.mainloop()
