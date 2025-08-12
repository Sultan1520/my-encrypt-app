import tkinter as tk
import ttkbootstrap as tb
from ttkbootstrap.constants import *
from tkinter import filedialog, messagebox
import threading
import os
import hashlib
import secrets
from io import BytesIO
import struct

MAGIC = b"MYENC1"
SALT_SIZE = 16
PBKDF2_ITERS = 100_000
CHUNK_SIZE = 64 * 1024


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive 32-byte key from password+salt."""
    return hashlib.pbkdf2_hmac("sha256", password.encode('utf-8'), salt, PBKDF2_ITERS, dklen=32)

def keystream_bytes(key: bytes, length: int, start_counter: int = 0):
    """Генерируем псевдослучайные байты через SHA256(key || counter) в режиме счётчика."""
    out = bytearray()
    counter = start_counter
    while len(out) < length:
        block = hashlib.sha256(key + counter.to_bytes(8, 'big')).digest()
        out += block
        counter += 1
    return bytes(out[:length])

def xor_bytes(data: bytes, key_stream: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, key_stream))


def encrypt_file(in_path: str, out_path: str, password: str, progress_callback=None):
    salt = secrets.token_bytes(SALT_SIZE)
    key = derive_key(password, salt)


    _, ext = os.path.splitext(in_path)
    ext_utf = ext.encode('utf-8')
    ext_len = len(ext_utf)
    if ext_len > 65535:
        raise ValueError("Слишком длинное расширение (нелепо)")

    with open(in_path, 'rb') as fin, open(out_path, 'wb') as fout:
        fout.write(MAGIC)
        fout.write(salt)
        fout.write(struct.pack(">H", ext_len))
        fout.write(ext_utf)

        total = os.path.getsize(in_path)
        processed = 0
        counter = 0

        while True:
            chunk = fin.read(CHUNK_SIZE)
            if counter == 0:
                chunk = MAGIC + chunk
            if not chunk:
                break
            ks = keystream_bytes(key, len(chunk), start_counter=counter)
            counter += (len(chunk) + 31) // 32  # каждые 32 байта — новый блок SHA256
            out_chunk = xor_bytes(chunk, ks)
            fout.write(out_chunk)
            processed += len(chunk)
            if progress_callback:
                progress_callback(processed, total)

def decrypt_file(in_path: str, out_folder: str, password: str, progress_callback=None):
    with open(in_path, 'rb') as fin:
        magic = fin.read(len(MAGIC))
        if magic != MAGIC:
            raise ValueError("Файл не в поддерживаемом формате (magic mismatch)")

        salt = fin.read(SALT_SIZE)
        ext_len_bytes = fin.read(2)
        if len(ext_len_bytes) < 2:
            raise ValueError("Повреждённый файл (нет длины расширения)")
        ext_len = struct.unpack(">H", ext_len_bytes)[0]
        ext = fin.read(ext_len).decode('utf-8') if ext_len > 0 else ''

        key = derive_key(password, salt)

        base_name = os.path.splitext(os.path.basename(in_path))[0]
        out_path = os.path.join(out_folder, base_name + ext)

        total = os.path.getsize(in_path)
        header_size = len(MAGIC) + SALT_SIZE + 2 + ext_len
        data_total = max(0, total - header_size)
        processed = 0
        counter = 0

        with open(out_path, 'wb') as fout:
            while True:
                chunk = fin.read(CHUNK_SIZE)
                if not chunk:
                    break
                ks = keystream_bytes(key, len(chunk), start_counter=counter)
                counter += (len(chunk) + 31) // 32
                out_chunk = xor_bytes(chunk, ks)

                if counter == (len(chunk) + 31) // 32:  # первый блок
                    if not out_chunk.startswith(MAGIC):
                        fout.close()
                        os.remove(out_path)  # удалить пустой или повреждённый файл
                        raise ValueError("Неверный пароль!")
                    out_chunk = out_chunk[len(MAGIC):]

                fout.write(out_chunk)
                processed += len(chunk)
                if progress_callback:
                    progress_callback(processed, data_total)

    return out_path

# ---- GUI ----
class EncryptApp:
    def __init__(self, root):
        self.root = root
        root.title("File Encryptor (edu)")
        root.geometry("650x350")
        root.resizable(False, False)

        # Основной фрейм
        frm = tb.Frame(root, padding=15)
        frm.pack(fill='both', expand=True)

        # Поле выбора файла
        self.in_path_var = tk.StringVar()
        row_file = tb.Frame(frm)
        row_file.pack(fill='x', pady=8)
        tb.Label(row_file, text="Исходный файл:", bootstyle="secondary").pack(side='left')
        tb.Entry(row_file, textvariable=self.in_path_var, width=50).pack(side='left', padx=6)
        tb.Button(row_file, text="Обзор", bootstyle="info-outline", command=self.browse_in).pack(side='left')

        # Формат
        row_fmt = tb.Frame(frm)
        row_fmt.pack(fill='x', pady=8)
        self.format_var = tk.StringVar(value=".myenc")
        tb.Label(row_fmt, text="Формат:", bootstyle="secondary").pack(side='left')
        tb.Combobox(row_fmt, textvariable=self.format_var,
                    values=[".myenc", ".secfile", ".crypt"], width=12).pack(side='left', padx=5)

        # Пароль
        row_pw = tb.Frame(frm)
        row_pw.pack(fill='x', pady=8)
        tb.Label(row_pw, text="Пароль:", bootstyle="secondary").pack(side='left')
        self.pw_entry = tb.Entry(row_pw, show='*', width=30)
        self.pw_entry.pack(side='left', padx=6)

        # Кнопки действий
        row_btns = tb.Frame(frm)
        row_btns.pack(fill='x', pady=12)
        tb.Button(row_btns, text="🔒 Зашифровать", bootstyle="success", command=self.start_encrypt).pack(side='left',
                                                                                                        padx=5)
        tb.Button(row_btns, text="🔓 Расшифровать", bootstyle="danger", command=self.start_decrypt).pack(side='left',
                                                                                                        padx=5)

        # Прогресс
        self.progress = tb.Progressbar(frm, orient='horizontal', mode='determinate', bootstyle="striped-success")
        self.progress.pack(fill='x', pady=10)

        # Статус
        self.status_var = tk.StringVar(value="Готово")
        tb.Label(frm, textvariable=self.status_var, bootstyle="inverse-secondary").pack(anchor='w', pady=5)

    def browse_in(self):
        path = filedialog.askopenfilename()
        if path:
            self.in_path_var.set(path)

    def set_status(self, text):
        self.status_var.set(text)

    def set_progress(self, val, total):
        if total <= 0:
            self.progress['value'] = 0
            return
        pct = (val / total) * 100
        self.progress['value'] = pct

    def start_encrypt(self):
        in_path = self.in_path_var.get().strip()
        password = self.pw_entry.get()
        if not in_path or not os.path.isfile(in_path):
            messagebox.showerror("Ошибка", "Выберите существующий входной файл")
            return
        if not password:
            messagebox.showerror("Ошибка", "Введите пароль")
            return

        out_path = filedialog.asksaveasfilename(defaultextension=self.format_var.get(),
                                                filetypes=[("Encrypted files", "*" + self.format_var.get()),
                                                           ("All files", "*.*")])

        if not out_path:
            return

        def progress_cb(processed, total):
            self.root.after(0, lambda: self.set_progress(processed, total))

        def worker():
            try:
                self.root.after(0, lambda: self.set_status("Шифрование..."))
                encrypt_file(in_path, out_path, password, progress_callback=progress_cb)
                self.root.after(0, lambda: self.set_status(f"Зашифровано: {out_path}"))
                messagebox.showinfo("Готово", f"Файл зашифрован и сохранён:\n{out_path}")
            except Exception as e:
                messagebox.showerror("Ошибка шифрования", str(e))
            finally:
                self.root.after(0, lambda: self.set_progress(0, 1))

        threading.Thread(target=worker, daemon=True).start()

    def start_decrypt(self):
        in_path = filedialog.askopenfilename(filetypes=[("MyEnc files", "*.myenc"), ("All files", "*.*")])
        if not in_path:
            return
        password = self.pw_entry.get()
        if not password:
            messagebox.showerror("Ошибка", "Введите пароль")
            return
        out_folder = filedialog.askdirectory(title="Папка для сохранения расшифрованного файла")
        if not out_folder:
            return

        def progress_cb(processed, total):
            self.root.after(0, lambda: self.set_progress(processed, total))

        def worker():
            try:
                self.root.after(0, lambda: self.set_status("Расшифровываю..."))
                out_file = decrypt_file(in_path, out_folder, password, progress_callback=progress_cb)
                self.root.after(0, lambda: self.set_status(f"Расшифровано: {out_file}"))
                messagebox.showinfo("Готово", f"Файл расшифрован:\n{out_file}")
            except Exception as e:
                messagebox.showerror("Ошибка расшифровки", str(e))
            finally:
                self.root.after(0, lambda: self.set_progress(0, 1))

        threading.Thread(target=worker, daemon=True).start()

if __name__ == "__main__":
    root = tb.Window(themename="superhero")
    app = EncryptApp(root)
    root.mainloop()
