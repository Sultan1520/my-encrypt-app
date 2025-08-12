import os
import tempfile
import struct
import secrets
import hashlib
from flask import Flask, render_template, request, send_file, flash, redirect, url_for
from werkzeug.utils import secure_filename
import requests


MAGIC = b"MYENC1"
SALT_SIZE = 16
PBKDF2_ITERS = 100_000
CHUNK_SIZE = 64 * 1024


MAX_CONTENT_LENGTH = 200 * 1024 * 1024

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "dev-secret")
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH


API_KEY = "c1a55456-1dcb-4e48-b6c6-8b5fabb5a859"

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/search", methods=["GET", "POST"])
def search_page():
    if request.method == "POST":
        part_number = request.form.get("part_number")
        if part_number:
            data = get_mouser_data(part_number)
            return render_template("result.html", data=data, part_number=part_number)
    return render_template("search.html")


def get_mouser_data(part_number):
    url = "https://api.mouser.com/api/v1/search/partnumber"
    payload = {
        "SearchByPartRequest": {
            "mouserPartNumber": part_number
        }
    }
    params = {"apiKey": API_KEY}
    try:
        resp = requests.post(url, params=params, json=payload, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        products = data.get("SearchResults", {}).get("Parts", [])
        return products
    except Exception as e:
        print("Ошибка:", e)
        return []



def derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode('utf-8'), salt, PBKDF2_ITERS, dklen=32)

def keystream_bytes(key: bytes, length: int, start_counter: int = 0):
    out = bytearray()
    counter = start_counter
    while len(out) < length:
        block = hashlib.sha256(key + counter.to_bytes(8, 'big')).digest()
        out += block
        counter += 1
    return bytes(out[:length])

def xor_bytes(data: bytes, key_stream: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, key_stream))



def encrypt_stream(fin, fout, in_filename: str, password: str, progress_cb=None):
    """
    fin - file-like opened for reading in binary
    fout - file-like opened for writing in binary
    in_filename - имя исходного файла (чтобы сохранить расширение)
    """
    salt = secrets.token_bytes(SALT_SIZE)
    key = derive_key(password, salt)


    _, ext = os.path.splitext(in_filename)
    ext_utf = ext.encode('utf-8')
    ext_len = len(ext_utf)
    if ext_len > 65535:
        raise ValueError("Слишком длинное расширение")


    fout.write(MAGIC)
    fout.write(salt)
    fout.write(struct.pack(">H", ext_len))
    fout.write(ext_utf)


    processed = 0
    counter = 0
    while True:
        chunk = fin.read(CHUNK_SIZE)
        if not chunk:
            break

        if counter == 0:
            chunk = MAGIC + chunk
        ks = keystream_bytes(key, len(chunk), start_counter=counter)
        counter += (len(chunk) + 31) // 32
        out_chunk = xor_bytes(chunk, ks)
        fout.write(out_chunk)
        processed += len(chunk)
        if progress_cb:
            progress_cb(processed)


def decrypt_stream(fin, fout, password: str, progress_cb=None):
    """
    fin - file-like opened for reading in binary (positioned at start of encrypted file)
    fout - file-like opened for writing in binary
    Возвращает (out_path_ext) или возбуждает ValueError при неверном формате / пароле
    """

    magic = fin.read(len(MAGIC))
    if magic != MAGIC:
        raise ValueError("Файл не в поддерживаемом формате (magic mismatch)")

    salt = fin.read(SALT_SIZE)
    ext_len_bytes = fin.read(2)
    if len(ext_len_bytes) < 2:
        raise ValueError("Повреждённый файл (неполный заголовок)")
    ext_len = struct.unpack(">H", ext_len_bytes)[0]
    ext = fin.read(ext_len).decode('utf-8') if ext_len > 0 else ''

    key = derive_key(password, salt)


    processed = 0
    counter = 0
    first_block_checked = False

    while True:
        chunk = fin.read(CHUNK_SIZE)
        if not chunk:
            break
        ks = keystream_bytes(key, len(chunk), start_counter=counter)
        counter += (len(chunk) + 31) // 32
        out_chunk = xor_bytes(chunk, ks)


        if not first_block_checked:
            first_block_checked = True
            if not out_chunk.startswith(MAGIC):
                raise ValueError("Неверный пароль или повреждённый файл")
            out_chunk = out_chunk[len(MAGIC):]

        fout.write(out_chunk)
        processed += len(chunk)
        if progress_cb:
            progress_cb(processed)

    return ext



@app.route("/encrypt", methods=["GET"])
def encrypt_page():
    return render_template("encrypt.html")


@app.route("/encrypt", methods=["POST"])
def encrypt_route():
    uploaded = request.files.get("file")
    password = (request.form.get("password") or "").strip()
    out_ext = request.form.get("out_ext") or ".myenc"

    if not uploaded or uploaded.filename == "":
        flash("Файл не выбран", "danger")
        return redirect(url_for("encrypt_page"))
    if not password:
        flash("Введите пароль", "danger")
        return redirect(url_for("encrypt_page"))

    filename = secure_filename(uploaded.filename)
    tmp_in = tempfile.NamedTemporaryFile(delete=False)
    tmp_in_name = tmp_in.name
    try:
        uploaded.stream.seek(0)
        while True:
            chunk = uploaded.stream.read(CHUNK_SIZE)
            if not chunk:
                break
            tmp_in.write(chunk)
        tmp_in.flush()
        tmp_in.close()

        tmp_out = tempfile.NamedTemporaryFile(delete=False)
        tmp_out_name = tmp_out.name
        tmp_out.close()

        with open(tmp_in_name, "rb") as fin, open(tmp_out_name, "wb") as fout:
            encrypt_stream(fin, fout, filename, password)

        out_filename = os.path.splitext(filename)[0] + out_ext
        return_data = send_file(tmp_out_name, as_attachment=True, download_name=out_filename)

        # В background: удалим временные файлы после отправки — здесь просто пометим на удаление
        @return_data.call_on_close
        def cleanup():
            try:
                os.remove(tmp_in_name)
            except:
                pass
            try:
                os.remove(tmp_out_name)
            except:
                pass

        return return_data

    except Exception as e:
        try:
            os.unlink(tmp_in_name)
        except:
            pass
        try:
            os.unlink(tmp_out_name)
        except:
            pass
        flash(f"Ошибка при шифровании: {e}", "danger")
        return redirect(url_for("encrypt_page"))


@app.route("/decrypt", methods=["POST"])
def decrypt_route():
    uploaded = request.files.get("file")
    password = (request.form.get("password") or "").strip()

    if not uploaded or uploaded.filename == "":
        flash("Файл не выбран", "danger")
        return redirect(url_for("encrypt_page"))
    if not password:
        flash("Введите пароль", "danger")
        return redirect(url_for("encrypt_page"))

    filename = secure_filename(uploaded.filename)
    tmp_in = tempfile.NamedTemporaryFile(delete=False)
    tmp_in_name = tmp_in.name
    try:
        uploaded.stream.seek(0)
        while True:
            chunk = uploaded.stream.read(CHUNK_SIZE)
            if not chunk:
                break
            tmp_in.write(chunk)
        tmp_in.flush()
        tmp_in.close()

        tmp_out = tempfile.NamedTemporaryFile(delete=False)
        tmp_out_name = tmp_out.name
        tmp_out.close()

        # расшифровываем
        with open(tmp_in_name, "rb") as fin, open(tmp_out_name, "wb") as fout:
            ext = decrypt_stream(fin, fout, password)

        # имя для скачивания: взять базу имени файла (без .myenc) и добавить ext
        base = os.path.splitext(filename)[0]
        out_filename = base + (ext or "")

        return_data = send_file(tmp_out_name, as_attachment=True, download_name=out_filename)

        @return_data.call_on_close
        def cleanup():
            try:
                os.remove(tmp_in_name)
            except:
                pass
            try:
                os.remove(tmp_out_name)
            except:
                pass

        return return_data

    except Exception as e:
        # удаляем возможные файлы
        try:
            os.unlink(tmp_in_name)
        except:
            pass
        try:
            os.unlink(tmp_out_name)
        except:
            pass
        flash(f"Ошибка при расшифровке: {e}", "danger")
        return redirect(url_for("encrypt_page"))


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
