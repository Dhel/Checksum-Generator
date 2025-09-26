import hashlib
import sys, os
import tkinter as tk
from tkinter import filedialog, messagebox



def browse_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        entry_file.delete(0, tk.END)
        entry_file.insert(0, file_path)
        btn_generate.config(state=tk.NORMAL)  # Enable generate button
        btn_clear.config(state=tk.NORMAL)
        btn_save.config(state=tk.NORMAL)

def generate_checksums():
    file_path = entry_file.get()
    if not file_path:
        messagebox.showwarning("No file", "Please select a file first.")
        return

    try:
        with open(file_path, "rb") as f:
            file_bytes = f.read()
            sha256_hash = hashlib.sha256(file_bytes).hexdigest()
            sha512_hash = hashlib.sha512(file_bytes).hexdigest()

        # SHA256
        txt_sha256.config(state=tk.NORMAL)
        txt_sha256.delete(1.0, tk.END)
        txt_sha256.insert(tk.END, sha256_hash)
        txt_sha256.config(state=tk.DISABLED)

        # SHA512
        txt_sha512.config(state=tk.NORMAL)
        txt_sha512.delete(1.0, tk.END)
        txt_sha512.insert(tk.END, sha512_hash)
        txt_sha512.config(state=tk.DISABLED)

    except Exception as e:
        messagebox.showerror("Error", f"Failed to generate checksum:\n{e}")

def copy_to_clipboard(textbox):
    checksum = textbox.get("1.0", tk.END).strip()
    if checksum:
        root.clipboard_clear()
        root.clipboard_append(checksum)
        root.update()  # Keeps clipboard content after app closes
        messagebox.showinfo("Copied", "Copied to clipboard!")

def copy_to_clipboard(textbox):
    textbox.config(state=tk.NORMAL)
    checksum = textbox.get(1.0, tk.END).strip()
    textbox.config(state=tk.DISABLED)

    if checksum:
        root.clipboard_clear()
        root.clipboard_append(checksum)
        messagebox.showinfo("Copied", "Copied to clipboard!")

def clear_fields():
    txt_sha256.config(state=tk.NORMAL)
    txt_sha256.delete(1.0, tk.END)
    txt_sha256.config(state=tk.DISABLED)

    txt_sha512.config(state=tk.NORMAL)
    txt_sha512.delete(1.0, tk.END)
    txt_sha512.config(state=tk.DISABLED)

    entry_file.delete(0, tk.END)

    btn_generate.config(state=tk.DISABLED)
    btn_clear.config(state=tk.DISABLED)
    btn_save.config(state=tk.DISABLED)

def save_checksums():
    file_path = entry_file.get()
    sha256 = txt_sha256.get(1.0, tk.END).strip()
    sha512 = txt_sha512.get(1.0, tk.END).strip()

    if not sha256 and not sha512:
        messagebox.showwarning("No checksum", "Please generate checksums first.")
        return

    # Suggest filename based on original file
    suggested_name = "checksums.txt"
    if file_path:
        base_name = os.path.basename(file_path)
        name, _ = os.path.splitext(base_name)
        suggested_name = f"{name}_checksum.txt"

    save_path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        initialfile=suggested_name,
        filetypes=[("Text Files", "*.txt")]
    )

    if save_path:
        try:
            with open(save_path, "w") as f:
                f.write("Checksums\n")
                f.write("="*40 + "\n")
                f.write(f"File: {os.path.basename(file_path)}\n\n")
                f.write(f"SHA256: {sha256}\n")
                f.write(f"SHA512: {sha512}\n")
            messagebox.showinfo("Saved", f"Checksums saved to:\n{save_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save file:\n{e}")

# Main Window
root = tk.Tk()
root.title("Checksum Generator by Dhel")

# Set custom icon

root.geometry("485x300")

# SHA256 Section
lbl_sha256 = tk.Label(root, text="SHA256")
lbl_sha256.grid(row=0, column=0, sticky="w", padx=10, pady=5)

frame256 = tk.Frame(root)
frame256.grid(row=1, column=0, padx=10, pady=5, sticky="w")

txt_sha256 = tk.Text(frame256, height=2, width=50, wrap="none", state=tk.DISABLED)
txt_sha256.grid(row=0, column=0, padx=5, pady=5)

scroll_x256 = tk.Scrollbar(frame256, orient="horizontal", command=txt_sha256.xview)
scroll_x256.grid(row=1, column=0, sticky="ew")

txt_sha256.config(xscrollcommand=scroll_x256.set)

btn_copy256 = tk.Button(frame256, text="Copy", command=lambda: copy_to_clipboard(txt_sha256))
btn_copy256.grid(row=0, column=1, padx=5, pady=5)



# SHA512 Section
lbl_sha512 = tk.Label(root, text="SHA512")
lbl_sha512.grid(row=2, column=0, sticky="w", padx=10, pady=5)

frame512 = tk.Frame(root)
frame512.grid(row=3, column=0, padx=10, pady=5, sticky="w")

txt_sha512 = tk.Text(frame512, height=2, width=50, wrap="none", state=tk.DISABLED)
txt_sha512.grid(row=0, column=0, padx=5, pady=5)

scroll_x512 = tk.Scrollbar(frame512, orient="horizontal", command=txt_sha512.xview)
scroll_x512.grid(row=1, column=0, sticky="ew")

txt_sha512.config(xscrollcommand=scroll_x512.set)

btn_copy512 = tk.Button(frame512, text="Copy", command=lambda: copy_to_clipboard(txt_sha512))
btn_copy512.grid(row=0, column=1, padx=5, pady=5)



# File Selection
entry_file = tk.Entry(root, width=60)
entry_file.grid(row=4, column=0, padx=10, pady=15, sticky="w")

# Buttons in one row
frame_buttons = tk.Frame(root)
frame_buttons.grid(row=5, column=0, columnspan=2, pady=10)

btn_browse = tk.Button(frame_buttons, text="Browse", width=12, command=browse_file)
btn_browse.grid(row=0, column=0, padx=5)

btn_generate = tk.Button(frame_buttons, text="Generate", width=12, command=generate_checksums, state=tk.DISABLED)
btn_generate.grid(row=0, column=1, padx=5)

btn_save = tk.Button(frame_buttons, text="Save", width=12, command=save_checksums, state=tk.DISABLED)
btn_save.grid(row=0, column=2, padx=5)

btn_clear = tk.Button(frame_buttons, text="Clear", width=12, command=clear_fields, state=tk.DISABLED)
btn_clear.grid(row=0, column=3, padx=5)


root.mainloop()
