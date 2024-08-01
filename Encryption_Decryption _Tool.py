import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import DES3
from hashlib import md5

def select_file():
    file_path = filedialog.askopenfilename()
    file_entry.delete(0, tk.END)
    file_entry.insert(0, file_path)


def encrypt_decrypt_file():
    operation = file_operation_var.get()
    file_path = file_entry.get()
    key = file_key_entry.get()

    if not file_path or not key:
        messagebox.showwarning("Input Error", "Please select a file and enter a key.")
        return

    key_hash = md5(key.encode('ascii')).digest()
    tdes_key = DES3.adjust_key_parity(key_hash)
    cipher = DES3.new(tdes_key, DES3.MODE_EAX, nonce=b'0')

    try:
        with open(file_path, 'rb') as input_file:
            file_bytes = input_file.read()
        
        if operation == '1':
            new_file_bytes = cipher.encrypt(file_bytes)
        else:
            new_file_bytes = cipher.decrypt(file_bytes)
        
        with open(file_path, 'wb') as output_file:
            output_file.write(new_file_bytes)
        
        messagebox.showinfo("Success", "File operation completed successfully.")
    except Exception as e:
        messagebox.showerror("Error", f"Operation failed: {str(e)}")

def encrypt_message(message, shift):
    encrypted_message = ""
    for char in message:
        if char.isalpha():
            shift_amount = shift % 26
            if char.islower():
                encrypted_message += chr((ord(char) - ord('a') + shift_amount) % 26 + ord('a'))
            elif char.isupper():
                encrypted_message += chr((ord(char) - ord('A') + shift_amount) % 26 + ord('A'))
        elif char.isdigit():
            encrypted_message += str((int(char) + shift) % 10)
        else:
            encrypted_message += char
    return encrypted_message

def decrypt_message(message, shift):
    return encrypt_message(message, -shift)

def process_message():
    message = message_entry.get("1.0", tk.END).strip()
    shift = shift_entry.get().strip()

    if not message:
        messagebox.showwarning("Input Error", "Please enter a message.")
        return
    if not shift.isdigit():
        messagebox.showwarning("Input Error", "Shift value must be a number.")
        return

    shift = int(shift)
    if message_encryption_var.get():
        result = encrypt_message(message, shift)
        description = "Encrypted Message:"
        border_color = "red"
    else:
        result = decrypt_message(message, shift)
        description = "Decrypted Message:"
        border_color = "green"

    result_window = tk.Toplevel(root)
    result_window.title("Result")
    result_label = tk.Label(result_window, text=description, font=("Arial", 15, "bold"))
    result_label.pack()
    result_text = tk.Text(result_window, height=10, width=56, font=("Arial", 15, "bold"), highlightthickness=4, highlightbackground=border_color)
    result_text.pack()
    result_text.insert(tk.END, f"\n{result}")
    result_text.config(state=tk.DISABLED)

def reset_fields():
    message_entry.delete("1.0", tk.END)
    shift_entry.delete(0, tk.END)
    file_entry.delete(0, tk.END)
    file_key_entry.delete(0, tk.END)
    message_encryption_var.set(True)
    file_operation_var.set('1')
    toggle_message_key_visibility(show=True)
    toggle_file_key_visibility(show=True)
    update_radiobutton_colors()

def update_radiobutton_colors():
    if message_encryption_var.get():
        encrypt_message_radio.config(bg="red", fg="white")
        decrypt_message_radio.config(bg="white", fg="black")
    else:
        encrypt_message_radio.config(bg="white", fg="black")
        decrypt_message_radio.config(bg="green", fg="white")

    if file_operation_var.get() == '1':
        encrypt_file_radio.config(bg="red", fg="white")
        decrypt_file_radio.config(bg="white", fg="black")
    else:
        encrypt_file_radio.config(bg="white", fg="black")
        decrypt_file_radio.config(bg="green", fg="white")

def toggle_message_key_visibility(show=None):
    if show is None:
        show = shift_entry.cget('show') == '*'
    if show:
        shift_entry.config(show='')
        toggle_message_key_button.config(text='Hide')
    else:
        shift_entry.config(show='*')
        toggle_message_key_button.config(text='Show')
    update_radiobutton_colors()

def toggle_file_key_visibility(show=None):
    if show is None:
        show = file_key_entry.cget('show') == '*'
    if show:
        file_key_entry.config(show='')
        toggle_file_key_button.config(text='Hide')
    else:
        file_key_entry.config(show='*')
        toggle_file_key_button.config(text='Show')

root = tk.Tk()
root.title("Message and File Encryption/Decryption Tool")

message_frame = tk.LabelFrame(root, text="Message Encryption/Decryption", padx=10, pady=10)
message_frame.pack(padx=10, pady=10, fill="x")

tk.Label(message_frame, text="Message:", font=("Arial", 15, "bold")).grid(row=0, column=0, padx=10, pady=10, sticky="w")
message_entry = tk.Text(message_frame, height=5, width=50, font=("Arial", 15, "bold"))
message_entry.grid(row=0, column=1, padx=10, pady=10, columnspan=2, sticky="ew")

tk.Label(message_frame, text="Key:", font=("Arial", 15, "bold")).grid(row=1, column=0, padx=10, pady=10, sticky="w")
shift_entry = tk.Entry(message_frame, font=("Arial", 15, "bold"), show="*")
shift_entry.grid(row=1, column=1, padx=10, pady=10, sticky="ew")

toggle_message_key_button = tk.Button(message_frame, text="Show", command=toggle_message_key_visibility, font=("Arial", 15, "bold"), bg="blue", fg="white")
toggle_message_key_button.grid(row=1, column=2, padx=10, pady=10, sticky="e")

message_encryption_var = tk.BooleanVar()
message_encryption_var.set(True)
encrypt_message_radio = tk.Radiobutton(message_frame, text="Encrypt", variable=message_encryption_var, value=True, font=("Arial", 15, "bold"), command=update_radiobutton_colors)
encrypt_message_radio.grid(row=2, column=0, padx=10, pady=10, sticky="w")
decrypt_message_radio = tk.Radiobutton(message_frame, text="Decrypt", variable=message_encryption_var, value=False, font=("Arial", 15, "bold"), command=update_radiobutton_colors)
decrypt_message_radio.grid(row=2, column=1, padx=10, pady=10, sticky="w")

tk.Button(message_frame, text="Process", command=process_message, font=("Arial", 18, "bold"), bg="blue", fg="white").grid(row=3, column=0, columnspan=3, padx=10, pady=10, sticky="ew")

file_frame = tk.LabelFrame(root, text="File Encryption/Decryption", padx=10, pady=10)
file_frame.pack(padx=10, pady=10, fill="x")

tk.Label(file_frame, text="Select a file:", font=("Arial", 15, "bold")).grid(row=0, column=0, padx=10, pady=10, sticky="w")
file_entry = tk.Entry(file_frame, width=50, font=("Arial", 15, "bold"))
file_entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")
tk.Button(file_frame, text="Browse", command=select_file, font=("Arial", 15, "bold")).grid(row=0, column=2, padx=10, pady=10)

tk.Label(file_frame, text="Key:", font=("Arial", 15, "bold")).grid(row=1, column=0, padx=10, pady=10, sticky="w")
file_key_entry = tk.Entry(file_frame, width=50, font=("Arial", 15, "bold"), show="*")
file_key_entry.grid(row=1, column=1, padx=10, pady=10, sticky="ew")

toggle_file_key_button = tk.Button(file_frame, text="Show", command=toggle_file_key_visibility, font=("Arial", 15, "bold"), bg="blue", fg="white")
toggle_file_key_button.grid(row=1, column=2, padx=10, pady=10, sticky="e")

file_operation_var = tk.StringVar()
file_operation_var.set('1')
encrypt_file_radio = tk.Radiobutton(file_frame, text="Encrypt", variable=file_operation_var, value='1', font=("Arial", 15, "bold"), command=update_radiobutton_colors)
encrypt_file_radio.grid(row=2, column=0, padx=10, pady=10, sticky="w")
decrypt_file_radio = tk.Radiobutton(file_frame, text="Decrypt", variable=file_operation_var, value='2', font=("Arial", 15, "bold"), command=update_radiobutton_colors)
decrypt_file_radio.grid(row=2, column=1, padx=10, pady=10, sticky="w")

tk.Button(file_frame, text="Process", command=encrypt_decrypt_file, font=("Arial", 18, "bold"), bg="blue", fg="white").grid(row=3, column=0, columnspan=3, padx=10, pady=10, sticky="ew")

tk.Button(root, text="Reset", command=reset_fields, font=("Arial", 15, "bold"), bg="green", fg="white").pack(padx=10, pady=10, fill="x")

update_radiobutton_colors() 

root.mainloop()
