import tkinter as tk
from tkinter import ttk, messagebox
from aes_encryption import aes_encrypt, aes_decrypt
from md5 import key_generation_hash
import os

def decrypt_message(encrypted_message, message_label,button):
    def on_decrypt():
        entered_key = key_entry.get()
        # Convert the entered key to bytes
        entered_key = entered_key.encode('utf-8')
        # Decrypt the message using the entered key
        entered_key = key_generation_hash(entered_key)
        try:
            decrypted_message = aes_decrypt(encrypted_message, entered_key)
            decrypt_message = decrypted_message.decode('utf-8')
            message_label.config(text=f"{decrypt_message}")
            button.pack_forget()  # Hide the Decrypt button after decryption
            decrypt_popup.destroy()  # Close the popup after decryption
        except Exception as e:
            result_label.config(text=f"Error: {str(e)}")

    decrypt_popup = tk.Toplevel()
    decrypt_popup.title("Decrypt Message")
    decrypt_popup.geometry("300x100")

    key_label = tk.Label(decrypt_popup, text="Enter the key:")
    key_label.pack(pady=5)

    key_entry = tk.Entry(decrypt_popup, width=40)
    key_entry.pack(pady=5)

    decrypt_button = tk.Button(decrypt_popup, text="Decrypt", command=on_decrypt)
    decrypt_button.pack(pady=5)

    result_label = tk.Label(decrypt_popup, text="")
    result_label.pack(pady=5)

def send_message_user1():
    message = message_entry_user1.get("1.0", tk.END).strip()  # Get text from tk.Text widget and strip any extra whitespace
        
    # Display the generated key in a custom popup window
    key_popup = tk.Toplevel()
    key_popup.title("Enter a Key")
    key_popup.geometry("300x100")
    
    key_label = tk.Label(key_popup, text="Please enter a key:")
    key_label.pack(pady=5)
    
    key_entry = tk.Entry(key_popup, width=40)
    key_entry.pack(pady=5)
    
    message = message.encode('utf-8')  # Convert message to bytes
    
    def submit_key():
        entered_key = key_entry.get()
        # Convert the entered key to bytes
        entered_key = entered_key.encode('utf-8')
        # You can now use the entered_key variable as needed
        key = key_generation_hash(entered_key)
        key_popup.destroy()
        
        encrypted_message = aes_encrypt(message, key)

        # Display plain message on User 1's side (Red background) in blue box
        user1_message_frame = tk.Frame(user1_frame, bg='blue', padx=10, pady=5, relief="solid", bd=2)
        user1_message_label = tk.Label(user1_message_frame, text=message, bg='blue', fg='white', wraplength=250)
        user1_message_label.pack(padx=5, pady=5)
        user1_message_frame.pack(pady=5, anchor="e")  # Align to the right

        # Display encrypted message on User 2's side (Yellow background) in green box
        user2_message_frame = tk.Frame(user2_frame, bg='green', padx=10, pady=5, relief="solid", bd=2)
        user2_message_label = tk.Label(user2_message_frame, text=encrypted_message, bg='green', fg='white', wraplength=250)
        user2_message_label.pack(padx=5, pady=5)
        user2_message_frame.pack(pady=5, anchor="w")  # Align to the left

        # Add Decrypt button below the encrypted message
        decrypt_button = tk.Button(user2_message_frame, text="Decrypt", command=lambda: decrypt_message(encrypted_message, user2_message_label,decrypt_button))
        decrypt_button.pack(pady=5)

        # Reset message input field
        message_entry_user1.delete("1.0", tk.END)
    
    submit_button = tk.Button(key_popup, text="Submit", command=submit_key)
    submit_button.pack(pady=5)
    

# Handle sending message from User 2 side
def send_message_user2():
    message = message_entry_user2.get("1.0", tk.END).strip()  # Get text from tk.Text widget and strip any extra whitespace
    
    # Display the generated key in a custom popup window
    key_popup = tk.Toplevel()
    key_popup.title("Enter a Key")
    key_popup.geometry("300x100")
    
    key_label = tk.Label(key_popup, text="Please enter a key:")
    key_label.pack(pady=5)
    
    key_entry = tk.Entry(key_popup, width=40)
    key_entry.pack(pady=5)
    
    message = message.encode('utf-8')  # Convert message to bytes
    
    def submit_key():
        entered_key = key_entry.get()
        # Convert the entered key to bytes
        entered_key = entered_key.encode('utf-8')
        # You can now use the entered_key variable as needed
        key = key_generation_hash(entered_key)
        key_popup.destroy()
    
        encrypted_message = aes_encrypt(message, key)
        
        # Display plain message on User 2's side (Yellow background) in blue box
        user2_message_frame = tk.Frame(user2_frame, bg='blue', padx=10, pady=5, relief="solid", bd=2)
        user2_message_label = tk.Label(user2_message_frame, text=message, bg='blue', fg='white', wraplength=250)
        user2_message_label.pack(padx=5, pady=5)
        user2_message_frame.pack(pady=5, anchor="e")  # Align to the right

        # Display encrypted message on User 1's side (Red background) in green box
        user1_message_frame = tk.Frame(user1_frame, bg='green', padx=10, pady=5, relief="solid", bd=2)
        user1_message_label = tk.Label(user1_message_frame, text=encrypted_message, bg='green', fg='white', wraplength=250)
        user1_message_label.pack(padx=5, pady=5)
        user1_message_frame.pack(pady=5, anchor="w")  # Align to the right
        
        # Add Decrypt button below the encrypted message
        decrypt_button_2 = tk.Button(user1_message_frame, text="Decrypt", command=lambda: decrypt_message(encrypted_message, user1_message_label,decrypt_button_2))
        decrypt_button_2.pack(pady=5)

        # Reset message input field
        message_entry_user2.delete("1.0", tk.END)
    
    submit_button = tk.Button(key_popup, text="Submit", command=submit_key)
    submit_button.pack(pady=5)

# Create UI
def create_ui():
    # Create main window and set the size to full screen
    root = tk.Tk()
    root.title("Secure Messaging System")
    # set to 500*500
    root.geometry("800x500")

    # Create main frame to split screen into two sections
    main_frame = tk.Frame(root)
    main_frame.pack(fill="both", expand=True)

    # Create User 1 frame (45% of screen, Red background)
    global user1_frame
    user1_frame = tk.Frame(main_frame, bg='brown', width=0, height=0)
    user1_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
    user1_label = tk.Label(user1_frame, text="USER 1", font=("Arial", 16, "bold"), bg='red', fg='white')
    user1_label.pack(pady=10)

    # Create User 2 frame (45% of screen, Yellow background)
    global user2_frame
    user2_frame = tk.Frame(main_frame, bg='green', width=0, height=0)
    user2_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
    user2_label = tk.Label(user2_frame, text="USER 2", font=("Arial", 16, "bold"), bg='yellow', fg='black')
    user2_label.pack(pady=10)

    # Configure grid weights for proper resizing
    main_frame.grid_columnconfigure(0, weight=45)
    main_frame.grid_columnconfigure(1, weight=45)
    main_frame.grid_rowconfigure(0, weight=1)

    # Bottom section for User 1 (Message input, dropdown, and send button)
    bottom_frame_user1 = tk.Frame(user1_frame, bg='white')
    bottom_frame_user1.pack(fill="x", padx=10, pady=10, side="bottom")

    # Text Entry Box for User 1 message input
    # Text Entry Box for User 1 message input
    global message_entry_user1
    message_entry_user1 = tk.Text(bottom_frame_user1, width=23, height=1,font=("Helvetica", 18))  # Changed to tk.Text and added height
    message_entry_user1.pack(side="left", padx=5)

    # Send Button for User 1
    send_button_user1 = tk.Button(bottom_frame_user1, text="Send", command=send_message_user1)
    send_button_user1.pack(side="left", padx=5)

    # Bottom section for User 2 (Message input, dropdown, and send button)
    bottom_frame_user2 = tk.Frame(user2_frame, bg='white')
    bottom_frame_user2.pack(fill="x", padx=10, pady=10, side="bottom")

    # Text Entry Box for User 2 message input
    global message_entry_user2
    message_entry_user2 = tk.Text(bottom_frame_user2, width=23, height=1,font=("Helvetica", 18))  # Changed to tk.Text and added height
    message_entry_user2.pack(side="left", padx=5)


    # Send Button for User 2
    send_button_user2 = tk.Button(bottom_frame_user2, text="Send", command=send_message_user2)
    send_button_user2.pack(side="left", padx=5)

    # Start the Tkinter event loop
    root.mainloop()

# Run the UI
create_ui()
