import tkinter as tk
from tkinter import filedialog, messagebox

def encrypt(plaintext, shift):
    ciphertext = ""
    for char in plaintext:
        if char.isalpha():
            if char.isupper():
                ciphertext += chr((ord(char) + shift - 65) % 26 + 65)
            else:
                ciphertext += chr((ord(char) + shift - 97) % 26 + 97)
        else:
            ciphertext += char
    return ciphertext

def decrypt(ciphertext, shift):
    plaintext = ""
    for char in ciphertext:
        if char.isalpha():
            if char.isupper():
                plaintext += chr((ord(char) - shift - 65) % 26 + 65)
            else:
                plaintext += chr((ord(char) - shift - 97) % 26 + 97)
        else:
            plaintext += char
    return plaintext

def on_encrypt():
    text = input_text.get("1.0", tk.END).strip()
    if text:
        try:
            shift = int(shift_entry.get())
            encrypted_text = encrypt(text, shift)
            output_text.delete("1.0", tk.END)
            output_text.insert(tk.END, encrypted_text)
        except ValueError:
            messagebox.showerror("Invalid Input", "Please enter a valid number for shift.")
    else:
        messagebox.showwarning("Empty Input", "Please enter text to encrypt.")

def on_decrypt():
    text = input_text.get("1.0", tk.END).strip()
    if text:
        try:
            shift = int(shift_entry.get())
            decrypted_text = decrypt(text, shift)
            output_text.delete("1.0", tk.END)
            output_text.insert(tk.END, decrypted_text)
        except ValueError:
            messagebox.showerror("Invalid Input", "Please enter a valid number for shift.")
    else:
        messagebox.showwarning("Empty Input", "Please enter text to decrypt.")

def on_encrypt_file():
    filename = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    if filename:
        with open(filename, "r") as file:
            content = file.read()
        try:
            shift = int(shift_entry.get())
            encrypted_content = encrypt(content, shift)
            save_file(encrypted_content)
        except ValueError:
            messagebox.showerror("Invalid Input", "Please enter a valid number for shift.")

def on_decrypt_file():
    filename = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    if filename:
        with open(filename, "r") as file:
            content = file.read()
        try:
            shift = int(shift_entry.get())
            decrypted_content = decrypt(content, shift)
            save_file(decrypted_content)
        except ValueError:
            messagebox.showerror("Invalid Input", "Please enter a valid number for shift.")

def save_file(content):
    filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
    if filename:
        with open(filename, "w") as file:
            file.write(content)

# GUI setup
root = tk.Tk()
root.title("Caesar Cipher")
root.configure(bg="#1E1E2C")

# Ensures the frame adjusts with the window size.
root.grid_columnconfigure(0, weight=1)
root.grid_rowconfigure(0, weight=1)

# Create the main frame
frame = tk.Frame(root, bg="#282A36")
frame.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")

# Configure the frame to expand with the window
frame.grid_columnconfigure(0, weight=1)
frame.grid_rowconfigure(2, weight=1)
frame.grid_rowconfigure(4, weight=1)

title_label = tk.Label(root, text="Caesar Cipher", font=("Helvetica", 16, "bold"), fg="white", bg="#1E1E2C")
title_label.grid(row=0, column=0, pady=10, sticky="n")

shift_label = tk.Label(frame, text="Shift:", font=("Helvetica", 12), fg="white", bg="#282A36")
shift_label.grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
shift_entry = tk.Entry(frame, width=5, font=("Helvetica", 12))
shift_entry.grid(row=0, column=1, padx=10, pady=5, sticky=tk.W)

input_label = tk.Label(frame, text="Input Text:", font=("Helvetica", 12), fg="white", bg="#282A36")
input_label.grid(row=1, column=0, columnspan=2, sticky=tk.W, padx=10, pady=5)

input_text = tk.Text(frame, height=5, width=40, font=("Helvetica", 12), wrap=tk.WORD)
input_text.grid(row=2, column=0, columnspan=2, padx=10, pady=5, sticky="nsew")

output_label = tk.Label(frame, text="Output Text:", font=("Helvetica", 12), fg="white", bg="#282A36")
output_label.grid(row=3, column=0, columnspan=2, sticky=tk.W, padx=10, pady=5)

output_text = tk.Text(frame, height=5, width=40, font=("Helvetica", 12), wrap=tk.WORD)
output_text.grid(row=4, column=0, columnspan=2, padx=10, pady=5, sticky="nsew")

button_frame = tk.Frame(frame, bg="#282A36")
button_frame.grid(row=5, column=0, columnspan=2, pady=10)

encrypt_button = tk.Button(button_frame, text="Encrypt", command=on_encrypt, bg="#50FA7B", fg="black", font=("Helvetica", 12, "bold"))
encrypt_button.grid(row=0, column=0, padx=10, pady=5)

decrypt_button = tk.Button(button_frame, text="Decrypt", command=on_decrypt, bg="#FF5555", fg="black", font=("Helvetica", 12, "bold"))
decrypt_button.grid(row=0, column=1, padx=10, pady=5)

encrypt_file_button = tk.Button(button_frame, text="Encrypt File", command=on_encrypt_file, bg="#8BE9FD", fg="black", font=("Helvetica", 12, "bold"))
encrypt_file_button.grid(row=1, column=0, padx=10, pady=5)

decrypt_file_button = tk.Button(button_frame, text="Decrypt File", command=on_decrypt_file, bg="#BD93F9", fg="black", font=("Helvetica", 12, "bold"))
decrypt_file_button.grid(row=1, column=1, padx=10, pady=5)

quit_button = tk.Button(frame, text="Quit", command=root.quit, bg="#6272A4", fg="black", font=("Helvetica", 12, "bold"))
quit_button.grid(row=6, column=0, columnspan=2, pady=10)

root.mainloop()
