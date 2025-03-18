import customtkinter as ctk
from tkinter import filedialog, messagebox
from PIL import Image, ImageDraw, ImageFont
import os
from Crypto.Cipher import AES, DES, Blowfish
from Crypto.Util.Padding import pad, unpad
import base64
from data_encryption import encrypt_phrase, decrypt_phrase
from watermarking import add_watermark
from image_steganography import encode_image, extract_data_from_image, decrypt_data

class SteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("MyStego")
        self.root.geometry("1000x800")
        self.root.resizable(False, False)

        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")

        self.algorithm_var = ctk.StringVar(value="AES")
        self.beginning_frame = ctk.CTkFrame(self.root)
        self.settings_frame = ctk.CTkFrame(self.root)
        self.main_frame = ctk.CTkFrame(self.root)
        self.status_bar = ctk.CTkLabel(self.root, text="", anchor="w")
        self.sidebar_expanded = True  
        self.active_tab = None  

        self.create_beginning_page()
        self.beginning_frame.pack(fill="both", expand=True)
        self.status_bar.pack(side="bottom", fill="x")

    def create_beginning_page(self):
        main_frame = ctk.CTkFrame(self.beginning_frame, fg_color="transparent")
        main_frame.pack(expand=True, pady=20)
        ctk.CTkLabel(main_frame, text="MyStego", font=("Helvetica", 24, "bold")).pack(pady=50)
        ctk.CTkButton(main_frame, text="Start", command=self.show_main_dashboard, corner_radius=10, height=40).pack(pady=20)
        ctk.CTkButton(main_frame, text="⚙️ Settings", command=self.show_settings_page, corner_radius=10, height=40).pack(pady=20)

    def create_settings_page(self):
        self.settings_frame.pack_forget()
        self.settings_frame = ctk.CTkFrame(self.root)
        self.settings_frame.pack(fill="both", expand=True, padx=20, pady=20)

        ctk.CTkLabel(self.settings_frame, text="Settings", font=("Helvetica", 18, "bold")).pack(pady=20)
        ctk.CTkButton(self.settings_frame, text="Toggle Appearance (Light/Dark)", command=self.toggle_appearance, corner_radius=10).pack(pady=10)
        ctk.CTkLabel(self.settings_frame, text="Select Default Algorithm:", font=("Helvetica", 12)).pack(pady=10)
        algo_options = ["AES", "DES", "Blowfish", "N/A"]
        algo_combobox = ctk.CTkOptionMenu(self.settings_frame, variable=self.algorithm_var, values=algo_options)
        algo_combobox.pack(pady=5)
        ctk.CTkButton(self.settings_frame, text="Back", command=self.show_beginning_page, corner_radius=10).pack(pady=20)

    def toggle_appearance(self):
        current_mode = ctk.get_appearance_mode()
        ctk.set_appearance_mode("Dark" if current_mode == "Light" else "Light")

    def show_beginning_page(self):
        self.settings_frame.pack_forget()
        self.main_frame.pack_forget()
        self.beginning_frame.pack(fill="both", expand=True)

    def show_settings_page(self):
        self.beginning_frame.pack_forget()
        self.main_frame.pack_forget()
        self.create_settings_page()

    def show_main_dashboard(self):
        self.beginning_frame.pack_forget()
        self.settings_frame.pack_forget()
        self.main_frame.pack_forget()
        self.main_frame = ctk.CTkFrame(self.root)
        self.main_frame.pack(fill="both", expand=True)
        self.create_main_dashboard()

    def create_main_dashboard(self):
        self.sidebar = ctk.CTkFrame(self.main_frame, width=150, corner_radius=10)
        self.sidebar.pack(side="left", fill="y", padx=(10, 0), pady=10)

        title_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        title_frame.pack(fill="x", pady=(10, 10))
        ctk.CTkLabel(title_frame, text="MyStego", font=("Helvetica", 16, "bold")).pack(side="left", padx=10)
        self.collapse_btn = ctk.CTkButton(
            title_frame, text=">>", width=30, height=30, corner_radius=5,
            command=self.toggle_sidebar, font=("Helvetica", 12)
        )
        self.collapse_btn.pack(side="right", padx=5)

        self.button_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        self.button_frame.pack(fill="y", expand=True)

        self.nav_buttons = {
            "📥 Embed": lambda: self.switch_tab("📥 Embed Message"),
            "📤 Unembed": lambda: self.switch_tab("📤 Unembed Message"),
            "🔒 Encrypt": lambda: self.switch_tab("🔒 Phrase Encryption"),
            "🔓 Decrypt": lambda: self.switch_tab("🔓 Phrase Decryption"),
            "💧 Watermark": lambda: self.switch_tab("💧 Watermark Image"),
            "⚙️ Settings": self.show_settings_page,  
            "🏠 Home": self.show_beginning_page
        }

        self.button_widgets = {}
        for text, command in self.nav_buttons.items():
            btn = ctk.CTkButton(
                self.button_frame,
                text=text,
                command=lambda cmd=command, txt=text: self.button_click(cmd, txt),
                width=120,
                height=40,
                corner_radius=10,
                font=("Helvetica", 12),
                hover_color="#4CAF50", 
                fg_color="#2E2E2E" if ctk.get_appearance_mode() == "Dark" else "#E0E0E0"
            )
            btn.pack(pady=5)
            self.button_widgets[text] = btn
            btn.bind("<Enter>", lambda e, t=text: self.show_tooltip(t))
            btn.bind("<Leave>", lambda e: self.hide_tooltip())

        self.content_frame = ctk.CTkFrame(self.main_frame)
        self.content_frame.pack(side="right", fill="both", expand=True, padx=(0, 10), pady=10)

        self.tabview = ctk.CTkTabview(self.content_frame)
        self.tabview.pack(fill="both", expand=True)
        self.tabview.add("📥 Embed Message")
        self.tabview.add("📤 Unembed Message")
        self.tabview.add("🔒 Phrase Encryption")
        self.tabview.add("🔓 Phrase Decryption")
        self.tabview.add("💧 Watermark Image")
        self.create_encode_tab(self.tabview.tab("📥 Embed Message"))
        self.create_decode_tab(self.tabview.tab("📤 Unembed Message"))
        self.create_phrase_encryption_tab(self.tabview.tab("🔒 Phrase Encryption"))
        self.create_phrase_decryption_tab(self.tabview.tab("🔓 Phrase Decryption"))
        self.create_watermark_tab(self.tabview.tab("💧 Watermark Image"))

        self.tooltip = ctk.CTkLabel(self.root, text="", font=("Helvetica", 10), corner_radius=5, fg_color="#FFFF99")
        self.tooltip.place_forget()

    def button_click(self, command, text):
        command()
        if text != "🏠 Home": 
            self.highlight_button(text)

    def highlight_button(self, active_text):
        for text, btn in self.button_widgets.items():
            if text == active_text:
                btn.configure(fg_color="#2196F3", text_color="white") 
                self.active_tab = text
            else:
                btn.configure(
                    fg_color="#2E2E2E" if ctk.get_appearance_mode() == "Dark" else "#E0E0E0",
                    text_color="white" if ctk.get_appearance_mode() == "Dark" else "black"
                )

    def switch_tab(self, tab_name):
        self.tabview.set(tab_name)

    def toggle_sidebar(self):
        if self.sidebar_expanded:
            self.sidebar.configure(width=50)
            for btn in self.button_widgets.values():
                btn.configure(text="", width=40)
            self.collapse_btn.configure(text="<<")
        else:
            self.sidebar.configure(width=150)
            for text, btn in self.button_widgets.items():
                btn.configure(text=text, width=120)
            self.collapse_btn.configure(text=">>")
        self.sidebar_expanded = not self.sidebar_expanded

    def show_tooltip(self, text):
        self.tooltip.configure(text=f"{text.split(' ', 1)[1]}")
        x, y = self.root.winfo_pointerxy()
        self.tooltip.place(x=x + 10, y=y + 10)

    def hide_tooltip(self):
        self.tooltip.place_forget()

    def create_encode_tab(self, tab):
        ctk.CTkLabel(tab, text="Selected Image:").pack(pady=5)
        self.encode_image_display = ctk.CTkLabel(tab, text="")
        self.encode_image_display.pack(pady=5)
        ctk.CTkButton(tab, text="🖼 Browse", command=self.select_image_encode, corner_radius=10).pack(pady=5)
        ctk.CTkLabel(tab, text="Enter Data to Hide:").pack(pady=5)
        self.encode_secret_data_entry = ctk.CTkEntry(tab, width=300)
        self.encode_secret_data_entry.pack(pady=5)
        ctk.CTkLabel(tab, text="Enter Security Key:").pack(pady=5)
        self.encode_key_entry = ctk.CTkEntry(tab, width=300, show="*")
        self.encode_key_entry.pack(pady=5)
        ctk.CTkButton(tab, text="🔒 Encode Data", command=self.encode_data, corner_radius=10).pack(pady=10)
        self.output_path_label = ctk.CTkLabel(tab, text="", text_color="blue")
        self.output_path_label.pack(pady=5)

    def create_decode_tab(self, tab):
        ctk.CTkLabel(tab, text="Selected Encoded Image:").pack(pady=5)
        self.decode_image_display = ctk.CTkLabel(tab, text="")
        self.decode_image_display.pack(pady=5)
        ctk.CTkButton(tab, text="🖼 Browse", command=self.select_image_decode, corner_radius=10).pack(pady=5)
        ctk.CTkLabel(tab, text="Enter Security Key:").pack(pady=5)
        self.decode_key_entry = ctk.CTkEntry(tab, width=300, show="*")
        self.decode_key_entry.pack(pady=5)
        ctk.CTkButton(tab, text="🔓 Decode Data", command=self.decode_data, corner_radius=10).pack(pady=10)
        self.decode_output_text = ctk.CTkTextbox(tab, height=100, width=300)
        self.decode_output_text.pack(pady=5)

    def create_phrase_encryption_tab(self, tab):
        input_frame = ctk.CTkFrame(tab)
        input_frame.pack(pady=10, padx=10, fill="x")
        ctk.CTkLabel(input_frame, text="Enter Phrase to Encrypt:").pack(pady=5)
        self.phrase_encrypt_entry = ctk.CTkEntry(input_frame, width=300)
        self.phrase_encrypt_entry.pack(pady=5)
        ctk.CTkLabel(input_frame, text="Enter Security Key:").pack(pady=5)
        self.phrase_encrypt_key_entry = ctk.CTkEntry(input_frame, width=300, show="*")
        self.phrase_encrypt_key_entry.pack(pady=5)
        button_frame = ctk.CTkFrame(tab)
        button_frame.pack(pady=10)
        ctk.CTkButton(button_frame, text="Encrypt", command=self.encrypt_phrase_action, corner_radius=10).pack(side="left", padx=5)
        ctk.CTkButton(button_frame, text="Save to File", command=self.save_encrypted_phrase, corner_radius=10).pack(side="left", padx=5)
        ctk.CTkLabel(tab, text="Encrypted Result:").pack(pady=5)
        self.phrase_encrypt_output_text = ctk.CTkTextbox(tab, height=100, width=400)
        self.phrase_encrypt_output_text.pack(pady=5)

    def create_phrase_decryption_tab(self, tab):
        input_frame = ctk.CTkFrame(tab)
        input_frame.pack(pady=10, padx=10, fill="x")
        ctk.CTkLabel(input_frame, text="Enter Encrypted Phrase:").pack(pady=5)
        self.phrase_decrypt_entry = ctk.CTkEntry(input_frame, width=300)
        self.phrase_decrypt_entry.pack(pady=5)
        ctk.CTkLabel(input_frame, text="Enter Security Key:").pack(pady=5)
        self.phrase_decrypt_key_entry = ctk.CTkEntry(input_frame, width=300, show="*")
        self.phrase_decrypt_key_entry.pack(pady=5)
        ctk.CTkButton(tab, text="Decrypt", command=self.decrypt_phrase_action, corner_radius=10).pack(pady=10)
        ctk.CTkLabel(tab, text="Decrypted Result:").pack(pady=5)
        self.phrase_decrypt_output_text = ctk.CTkTextbox(tab, height=100, width=400)
        self.phrase_decrypt_output_text.pack(pady=5)

    def create_watermark_tab(self, tab):
        ctk.CTkLabel(tab, text="Selected Image:").pack(pady=5)
        self.watermark_image_display = ctk.CTkLabel(tab, text="")
        self.watermark_image_display.pack(pady=5)
        ctk.CTkButton(tab, text="🖼 Browse", command=self.select_image_watermark, corner_radius=10).pack(pady=5)
        ctk.CTkLabel(tab, text="Enter Watermark Text:").pack(pady=5)
        self.watermark_text_entry = ctk.CTkEntry(tab, width=300)
        self.watermark_text_entry.pack(pady=5)
        ctk.CTkButton(tab, text="💧 Apply Watermark", command=self.apply_watermark, corner_radius=10).pack(pady=10)
        self.watermark_output_path_label = ctk.CTkLabel(tab, text="", text_color="blue")
        self.watermark_output_path_label.pack(pady=5)

    def resize_image(self, image_path, max_size=(200, 200)):
        image = Image.open(image_path)
        image.thumbnail(max_size, Image.Resampling.LANCZOS)
        return ctk.CTkImage(light_image=image, dark_image=image, size=max_size)

    def select_image_encode(self):
        self.image_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.bmp")])
        if self.image_path:
            photo = self.resize_image(self.image_path)
            self.encode_image_display.configure(image=photo)
            self.encode_image_display.image = photo

    def select_image_decode(self):
        self.encoded_image_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.bmp")])
        if self.encoded_image_path:
            photo = self.resize_image(self.encoded_image_path)
            self.decode_image_display.configure(image=photo)
            self.decode_image_display.image = photo

    def select_image_watermark(self):
        self.watermark_image_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.bmp")])
        if self.watermark_image_path:
            photo = self.resize_image(self.watermark_image_path)
            self.watermark_image_display.configure(image=photo)
            self.watermark_image_display.image = photo

    def encode_data(self):
        if not hasattr(self, 'image_path'):
            messagebox.showerror("Error", "Please select an image first.")
            return
        output_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Files", "*.png")])
        if not output_path:
            return
        key = self.encode_key_entry.get().strip()
        success = encode_image(self.image_path, self.encode_secret_data_entry.get(), key, self.algorithm_var.get(), output_path)
        if success:
            self.output_path_label.configure(text=f"File saved at: {output_path}")
            self.status_bar.configure(text="Data encoded successfully!")
            messagebox.showinfo("Success", "Data encoded successfully!")
        else:
            self.status_bar.configure(text="Error encoding data.")

    def decode_data(self):
        if not hasattr(self, 'encoded_image_path'):
            messagebox.showerror("Error", "Please select an encoded image first.")
            return
        extracted_data = extract_data_from_image(self.encoded_image_path)
        if extracted_data is None:
            self.decode_output_text.delete("0.0", "end")
            self.decode_output_text.insert("0.0", "Error extracting data")
            self.status_bar.configure(text="Error extracting data.")
            return
        key = self.decode_key_entry.get().strip()
        try:
            msg = decrypt_data(self.algorithm_var.get(), key, extracted_data)
            self.status_bar.configure(text="Data decoded successfully!")
        except Exception as e:
            msg = f"Error decrypting data: {e}"
            self.status_bar.configure(text="Error decrypting data.")
        self.decode_output_text.delete("0.0", "end")
        self.decode_output_text.insert("0.0", msg)

    def encrypt_phrase_action(self):
        phrase = self.phrase_encrypt_entry.get().strip()
        key = self.phrase_encrypt_key_entry.get().strip()
        if not phrase or not key:
            messagebox.showerror("Error", "Please enter both a phrase and a key.")
            return
        encrypted = encrypt_phrase(self.algorithm_var.get(), key, phrase)
        if encrypted:
            self.phrase_encrypt_output_text.delete("0.0", "end")
            self.phrase_encrypt_output_text.insert("0.0", encrypted)
            self.status_bar.configure(text="Phrase encrypted successfully!")
        else:
            self.phrase_encrypt_output_text.delete("0.0", "end")
            self.phrase_encrypt_output_text.insert("0.0", "Error encrypting phrase")
            self.status_bar.configure(text="Error encrypting phrase.")

    def save_encrypted_phrase(self):
        encrypted_text = self.phrase_encrypt_output_text.get("0.0", "end").strip()
        if not encrypted_text or encrypted_text == "Error encrypting phrase":
            messagebox.showerror("Error", "Please encrypt a phrase first.")
            return
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt")],
            title="Save Encrypted Phrase"
        )
        if not file_path:
            return
        try:
            with open(file_path, 'w') as file:
                file.write(encrypted_text)
            self.status_bar.configure(text=f"Encrypted phrase saved to {file_path}")
            messagebox.showinfo("Success", f"Encrypted phrase saved to {file_path}")
        except Exception as e:
            self.status_bar.configure(text="Error saving file")
            messagebox.showerror("Error", f"Failed to save file: {e}")

    def decrypt_phrase_action(self):
        encrypted_phrase = self.phrase_decrypt_entry.get().strip()
        key = self.phrase_decrypt_key_entry.get().strip()
        if not encrypted_phrase or not key:
            messagebox.showerror("Error", "Please enter both an encrypted phrase and a key.")
            return
        decrypted = decrypt_phrase(self.algorithm_var.get(), key, encrypted_phrase)
        if decrypted:
            self.phrase_decrypt_output_text.delete("0.0", "end")
            self.phrase_decrypt_output_text.insert("0.0", decrypted)
            self.status_bar.configure(text="Phrase decrypted successfully!")
        else:
            self.phrase_decrypt_output_text.delete("0.0", "end")
            self.phrase_decrypt_output_text.insert("0.0", "Error decrypting phrase")
            self.status_bar.configure(text="Error decrypting phrase.")

    def apply_watermark(self):
        if not hasattr(self, 'watermark_image_path'):
            messagebox.showerror("Error", "Please select an image first.")
            return
        output_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Files", "*.png")])
        if not output_path:
            return
        watermark_text = self.watermark_text_entry.get().strip()
        success = add_watermark(self.watermark_image_path, watermark_text, output_path)
        if success:
            self.watermark_output_path_label.configure(text=f"File saved at: {output_path}")
            self.status_bar.configure(text="Watermark applied successfully!")
            messagebox.showinfo("Success", "Watermark applied successfully!")
        else:
            self.status_bar.configure(text="Error applying watermark.")
