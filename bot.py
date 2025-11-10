# bot_full_features.py
import os
import logging
import base64
import re
import json
import tempfile
import shutil
from io import BytesIO
from zipfile import ZipFile, ZIP_DEFLATED
from xml.dom import minidom
import aiohttp
from dotenv import load_dotenv

from aiogram import Bot, Dispatcher, types
from aiogram.types import ContentType, InlineKeyboardButton, InlineKeyboardMarkup
from aiogram.utils import executor
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BOT_TOKEN = os.getenv("BOT_TOKEN")
if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN not found in environment")

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher(bot)

# --- load keys with labels ---
def load_key_pairs(prefix: str):
    pairs = []  # list of (label, key_bytes, iv_bytes)
    idx = 1
    while True:
        key_name = f"{prefix}_KEY_HEX" if idx == 1 else f"{prefix}_KEY_HEX_{idx}"
        iv_name = f"{prefix}_IV_HEX" if idx == 1 else f"{prefix}_IV_HEX_{idx}"
        key_hex = os.getenv(key_name)
        iv_hex = os.getenv(iv_name)
        if not key_hex or not iv_hex:
            break
        try:
            pairs.append((key_name, bytes.fromhex(key_hex), bytes.fromhex(iv_hex)))
        except Exception as e:
            logger.warning(f"Invalid hex for {key_name}/{iv_name}: {e}")
        idx += 1
    return pairs

TEXT_KEY_PAIRS = load_key_pairs("AES_TEXT")       # AES-256-CBC keys for text files
ARCHIVE_KEY_PAIRS = load_key_pairs("AES_ARCHIVE") # AES-128-CBC keys for archive inner files

# --- helper crypto routines ---
def aes_cbc_decrypt_raw(data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    dec = cipher.decrypt(data)
    return unpad(dec, AES.block_size)

def aes_cbc_encrypt_raw(data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(data, AES.block_size))

def try_decrypt_with_pairs(data: bytes, pairs):
    """
    Try each (label, key, iv) and return (label, decrypted_bytes) on success.
    """
    last_exc = None
    for label, key, iv in pairs:
        try:
            dec = aes_cbc_decrypt_raw(data, key, iv)
            return label, dec
        except Exception as e:
            last_exc = e
            continue
    raise RuntimeError("No key succeeded") from last_exc

# --- archive processing helpers ---
def list_zip_infos(zip_bytes: bytes):
    with ZipFile(BytesIO(zip_bytes)) as z:
        return z.infolist()

def find_first_data_file_in_zip(z: ZipFile):
    for name in z.namelist():
        low = name.lower()
        if low.endswith((".sig", ".rsa", ".pem", ".zip.sha")) or name.endswith("/"):
            continue
        return name
    return None

def process_encrypted_zip_bytes(zip_bytes: bytes):
    """
    For archives that contain an encrypted archive/file inside.
    Find first candidate file, decrypt with ARCHIVE_KEY_PAIRS (AES-128-CBC), return filename_out, bytes_out.
    """
    with ZipFile(BytesIO(zip_bytes)) as z:
        candidate = find_first_data_file_in_zip(z)
        if not candidate:
            raise RuntimeError("No encrypted file found inside ZIP")
        enc_bytes = z.read(candidate)
        label, dec = try_decrypt_with_pairs(enc_bytes, ARCHIVE_KEY_PAIRS)
        out_name = os.path.basename(candidate)
        if out_name.endswith(".enc"):
            out_name = out_name[:-4]
        return out_name, dec, label

# --- text processing helpers ---
def try_parse_json_or_xml_and_pretty(dec_bytes: bytes):
    # try JSON
    try:
        obj = json.loads(dec_bytes.decode("utf-8"))
        pretty = json.dumps(obj, ensure_ascii=False, indent=2)
        return ".json", pretty.encode("utf-8")
    except Exception:
        pass
    # try XML
    try:
        dom = minidom.parseString(dec_bytes)
        pretty = dom.toprettyxml(indent="  ")
        return ".xml", pretty.encode("utf-8")
    except Exception:
        pass
    # fallback raw
    return ".txt", dec_bytes

def process_encrypted_text_bytes(raw_bytes: bytes):
    """
    raw_bytes is expected to be base64-encoded AES-256-CBC ciphertext.
    Try all text keys, return (out_name_ext, out_bytes, used_label)
    """
    s = raw_bytes.decode("utf-8", errors="ignore").strip()
    try:
        b64 = base64.b64decode(s)
    except Exception as e:
        raise ValueError("Not base64 or corrupted") from e
    label, dec = try_decrypt_with_pairs(b64, TEXT_KEY_PAIRS)
    ext, pretty_bytes = try_parse_json_or_xml_and_pretty(dec)
    return ext, pretty_bytes, label

# --- recursive archive walker & processor ---
def process_archive_recursive_and_build(zip_bytes: bytes, action: str, encrypt_choice_label: str = None):
    """
    action: 'decrypt' or 'encrypt'
    encrypt_choice_label: for encryption, the label (key var name) to use for text files (AES-256).
    Returns bytes of the resulting zip.
    """
    tmpdir = tempfile.mkdtemp(prefix="botproc_")
    try:
        # extract incoming zip into tmpdir preserving structure
        inzip = ZipFile(BytesIO(zip_bytes))
        inzip.extractall(tmpdir)
        inzip.close()

        # walk files
        for root, dirs, files in os.walk(tmpdir):
            for fname in files:
                fpath = os.path.join(root, fname)
                relpath = os.path.relpath(fpath, tmpdir)
                lower = fname.lower()

                # if file itself is a zip and action applies to its internals? We'll treat nested zip similarly: replace it with processed zip if needed
                if lower.endswith(".zip"):
                    # read bytes
                    with open(fpath, "rb") as rf:
                        nested_bytes = rf.read()
                    # For decrypt action: if nested zip contains an encrypted file inside -> decrypt it and replace nested zip with new bytes (file may be just container)
                    if action == "decrypt":
                        try:
                            out_name, out_bytes, used_label = process_encrypted_zip_bytes(nested_bytes)
                            # replace the nested zip file with a zip that contains the decrypted inner file with original relative name
                            # We'll create a new zip: same filename as original (but content is the decrypted file)
                            new_zip_bytes = BytesIO()
                            with ZipFile(new_zip_bytes, "w", ZIP_DEFLATED) as wz:
                                wz.writestr(out_name, out_bytes)
                            with open(fpath, "wb") as wf:
                                wf.write(new_zip_bytes.getvalue())
                        except Exception:
                            # if cannot decrypt inner, leave nested zip unchanged
                            pass
                    elif action == "encrypt":
                        # if encrypting, we could encrypt a file INSIDE nested zips? For simplicity, skip nested zip encryption of internal members
                        pass
                    continue

                # For text-like files: try detect & process
                # We'll try to read file as text; if it's base64->AES enc, we'll decrypt when action == 'decrypt'
                # For 'encrypt' we will minify JSON/XML and then encrypt+base64 and replace contents
                try:
                    with open(fpath, "rb") as rf:
                        content = rf.read()
                except Exception:
                    continue

                if action == "decrypt":
                    # Try: is this a base64-looking text -> attempt text decrypt
                    try:
                        ext, pretty_bytes, used_label = process_encrypted_text_bytes(content)
                        # write decoded pretty file with appropriate extension (replace filename)
                        newname = os.path.splitext(fpath)[0] + ext
                        with open(newname, "wb") as wf:
                            wf.write(pretty_bytes)
                        # remove old file if extension differs
                        if newname != fpath:
                            os.remove(fpath)
                    except Exception:
                        # not decryptable text, leave it as-is
                        pass
                elif action == "encrypt":
                    # attempt to minify JSON/XML; if success, encrypt using chosen key label
                    # find that key pair
                    if encrypt_choice_label is None:
                        continue
                    chosen = None
                    for label, key, iv in TEXT_KEY_PAIRS:
                        if label == encrypt_choice_label:
                            chosen = (key, iv)
                            break
                    if not chosen:
                        continue
                    try:
                        # try JSON
                        t = content.decode("utf-8")
                        try:
                            obj = json.loads(t)
                            minified = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
                        except Exception:
                            # try XML minify: remove whitespace between tags
                            try:
                                dom = minidom.parseString(t)
                                # produce no-indent one-line output
                                minified = "".join([n.toxml() for n in dom.childNodes]).encode("utf-8")
                            except Exception:
                                # not JSON/XML -> skip
                                continue
                        key, iv = chosen
                        cipher_bytes = aes_cbc_encrypt_raw(minified, key, iv)
                        b64 = base64.b64encode(cipher_bytes)
                        with open(fpath, "wb") as wf:
                            wf.write(b64)
                    except Exception:
                        pass

        # after processing all files, rezip tmpdir into bytes
        out_bytes_io = BytesIO()
        with ZipFile(out_bytes_io, "w", ZIP_DEFLATED) as zout:
            for root, dirs, files in os.walk(tmpdir):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    arcname = os.path.relpath(fpath, tmpdir)
                    zout.write(fpath, arcname)
        return out_bytes_io.getvalue()
    finally:
        shutil.rmtree(tmpdir)

# --- simple state storage for interactive confirmations ---
# maps chat_id -> { 'type': ..., 'data': ... }
PENDING = {}

# --- Inline keyboards ---
def make_confirm_download_kb(url):
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(InlineKeyboardButton("Скачать и обработать", callback_data=f"link_dl|{url}"),
           InlineKeyboardButton("Отмена", callback_data="cancel"))
    return kb

def make_archive_action_kb():
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(InlineKeyboardButton("Расшифровать архив", callback_data="archive|decrypt"),
           InlineKeyboardButton("Зашифровать архив", callback_data="archive|encrypt"),
           InlineKeyboardButton("Отмена", callback_data="cancel"))
    return kb

def make_key_choice_kb(pairs_prefix="AES_TEXT"):
    kb = InlineKeyboardMarkup(row_width=1)
    # list TEXT_KEY_PAIRS labels
    for label, key, iv in TEXT_KEY_PAIRS:
        kb.add(InlineKeyboardButton(label, callback_data=f"choose_text_key|{label}"))
    kb.add(InlineKeyboardButton("Отмена", callback_data="cancel"))
    return kb

# --- Handlers ---
@dp.message_handler(commands=["start", "help"])
async def cmd_start(message: types.Message):
    await message.reply("Приветствую! Пришлите зашифрованный файл, архив или ссылку на файл — я его расшифрую.")

@dp.message_handler(commands=["changes"])
async def cmd_changes(message: types.Message):
    changes = (
        "📝 Последние изменения:\n"
        "*Бот теперь может скачивать и расшифровывать файлы по ссылке.\n"
        "*Бот теперь отвечает на исходное сообщение расшифрованным файлом.\n"
        "*Добавлена поддержка расшифровки файлов Shades.\n"
    )
    await message.reply(changes)

# handle links: show metadata then ask to download/process
@dp.message_handler(lambda message: re.search(r'https?://\S+', message.text or ""))
async def handle_link(message: types.Message):
    url = re.search(r'(https?://\S+)', message.text).group(1)
    await message.reply("Собираю мета-информацию...")
    try:
        async with aiohttp.ClientSession() as session:
            async with session.head(url, timeout=20) as resp:
                headers = resp.headers
            # get last-modified or fallback
            last_mod = headers.get("Last-Modified") or headers.get("Date") or "Unknown"
            size = headers.get("Content-Length") or "Unknown"
            cd = headers.get("Content-Disposition")
            fname = None
            if cd:
                m = re.search(r'filename="?([^";]+)"?', cd)
                if m:
                    fname = m.group(1)
            if not fname:
                fname = os.path.basename(url.split("?")[0]) or "file"
        text = f"Файл: {fname}\nРазмер (байт): {size}\nПоследнее изменение: {last_mod}\n\nСкачать и обработать?"
        await message.reply(text, reply_markup=make_confirm_download_kb(url))
        PENDING[message.chat.id] = {"type": "link_info", "url": url, "fname": fname}
    except Exception as e:
        await message.reply(f"Ошибка при получении информации: {e}")

# handle doc upload: if zip => ask action, else attempt to process single file
@dp.message_handler(content_types=ContentType.DOCUMENT)
async def handle_document(message: types.Message):
    doc = message.document
    filename = doc.file_name or "file"
    file_obj = await bot.get_file(doc.file_id)
    file_bytes = await bot.download_file(file_obj.file_path)
    data = file_bytes.read()
    lower = filename.lower()
    if lower.endswith(".zip"):
        await message.reply("Получен ZIP. Что делаем?", reply_markup=make_archive_action_kb())
        PENDING[message.chat.id] = {"type": "archive_uploaded", "bytes": data, "orig_name": filename}
        return
    # non-zip file: ask encrypt/decrypt choice
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(InlineKeyboardButton("Расшифровать", callback_data="single|decrypt"),
           InlineKeyboardButton("Зашифровать", callback_data="single|encrypt"),
           InlineKeyboardButton("Отмена", callback_data="cancel"))
    PENDING[message.chat.id] = {"type": "single_file", "bytes": data, "orig_name": filename}
    await message.reply("Выберите действие для файла:", reply_markup=kb)

# callbacks
@dp.callback_query_handler(lambda c: True)
async def process_callback(cb: types.CallbackQuery):
    data = cb.data
    chat_id = cb.message.chat.id
    await cb.answer()  # acknowledge

    if data == "cancel":
        PENDING.pop(chat_id, None)
        await cb.message.reply("Отменено.")
        return

    if data.startswith("link_dl|"):
        # user confirmed download and processing of a link
        url = data.split("|",1)[1]
        await cb.message.reply("Скачиваю файл и начинаю обработку...")
        pending = PENDING.get(chat_id)
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as resp:
                    if resp.status != 200:
                        raise RuntimeError(f"HTTP {resp.status}")
                    content = await resp.read()
            # treat downloaded file similar to upload
            name = pending.get("fname") if pending else os.path.basename(url)
            if name.lower().endswith(".zip") or url.lower().endswith(".zip") or url.lower().endswith(".zip.enc"):
                # process as archive: ask decrypt/encrypt
                PENDING[chat_id] = {"type": "archive_uploaded", "bytes": content, "orig_name": name}
                await cb.message.reply("Скачан архив. Что делаем?", reply_markup=make_archive_action_kb())
            else:
                # single file
                PENDING[chat_id] = {"type": "single_file", "bytes": content, "orig_name": name}
                kb = InlineKeyboardMarkup(row_width=2)
                kb.add(InlineKeyboardButton("Расшифровать", callback_data="single|decrypt"),
                       InlineKeyboardButton("Зашифровать", callback_data="single|encrypt"),
                       InlineKeyboardButton("Отмена", callback_data="cancel"))
                await cb.message.reply("Файл скачан. Выберите действие:", reply_markup=kb)
        except Exception as e:
            await cb.message.reply(f"Ошибка при скачивании: {e}")
        return

    if data.startswith("archive|"):
        # user chose action for uploaded archive
        _, action = data.split("|",1)
        pending = PENDING.get(chat_id)
        if not pending or pending.get("type") != "archive_uploaded":
            await cb.message.reply("Нет загруженного архива в очереди.")
            return
        bytes_archive = pending["bytes"]
        orig_name = pending.get("orig_name","archive.zip")
        await cb.message.reply(f"Начинаю {action} архива — это может занять время...")
        try:
            if action == "decrypt":
                out_bytes = process_archive_recursive_and_build(bytes_archive, action="decrypt")
                out_name = os.path.splitext(orig_name)[0] + "_decrypted.zip"
                await bot.send_document(chat_id, types.InputFile(BytesIO(out_bytes), filename=out_name))
                await cb.message.reply("Готово.")
            elif action == "encrypt":
                # ask which text key to use
                PENDING[chat_id] = {"type":"archive_encrypt_choice", "bytes": bytes_archive, "orig_name": orig_name}
                if not TEXT_KEY_PAIRS:
                    await cb.message.reply("Нет текстовых ключей для шифрования (AES_TEXT_*). Добавьте в env.")
                    return
                await cb.message.reply("Выберите ключ для шифрования текстовых файлов в архиве:", reply_markup=make_key_choice_kb())
        except Exception as e:
            await cb.message.reply(f"Ошибка при обработке архива: {e}")
        return

    if data.startswith("single|"):
        _, action = data.split("|",1)
        pending = PENDING.get(chat_id)
        if not pending or pending.get("type") != "single_file":
            await cb.message.reply("Нет файла в очереди.")
            return
        b = pending["bytes"]
        name = pending.get("orig_name","file")
        await cb.message.reply("Выполняю операцию...")
        try:
            if action == "decrypt":
                # attempt text decrypt or archive inner decrypt
                if name.lower().endswith(".zip"):
                    out_name, out_bytes, _ = process_encrypted_zip_bytes(b)
                    await bot.send_document(chat_id, types.InputFile(BytesIO(out_bytes), filename=out_name))
                else:
                    ext, outb, label = process_encrypted_text_bytes(b)
                    out_name = os.path.splitext(name)[0] + ext
                    await bot.send_document(chat_id, types.InputFile(BytesIO(outb), filename=out_name))
                await cb.message.reply("Готово.")
            elif action == "encrypt":
                # need to ask which key
                PENDING[chat_id] = {"type":"single_encrypt_choice", "bytes": b, "orig_name": name}
                if not TEXT_KEY_PAIRS:
                    await cb.message.reply("Нет текстовых ключей для шифрования (AES_TEXT_*). Добавьте в env.")
                    return
                await cb.message.reply("Выберите ключ для шифрования:", reply_markup=make_key_choice_kb())
        except Exception as e:
            await cb.message.reply(f"Ошибка: {e}")
        return

    if data.startswith("choose_text_key|"):
        _, label = data.split("|",1)
        pending = PENDING.get(chat_id)
        if not pending:
            await cb.message.reply("Нечего шифровать.")
            return
        ptype = pending.get("type")
        if ptype == "single_encrypt_choice":
            b = pending["bytes"]
            name = pending.get("orig_name","file")
            # perform encryption of single file
            # find key
            chosen = None
            for lab, key, iv in TEXT_KEY_PAIRS:
                if lab == label:
                    chosen = (key, iv)
                    break
            if not chosen:
                await cb.message.reply("Ключ не найден.")
                return
            try:
                # try minify JSON/XML
                t = b.decode("utf-8", errors="ignore")
                try:
                    obj = json.loads(t)
                    minified = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
                except Exception:
                    try:
                        dom = minidom.parseString(t)
                        minified = "".join([n.toxml() for n in dom.childNodes]).encode("utf-8")
                    except Exception:
                        await cb.message.reply("Файл не распознан как JSON/XML, шифрование пропущено.")
                        return
                key, iv = chosen
                cipher_bytes = aes_cbc_encrypt_raw(minified, key, iv)
                b64 = base64.b64encode(cipher_bytes)
                out_name = os.path.splitext(name)[0] + ".enc.b64"
                await bot.send_document(chat_id, types.InputFile(BytesIO(b64), filename=out_name))
                await cb.message.reply("Файл зашифрован.")
            except Exception as e:
                await cb.message.reply(f"Ошибка шифрования: {e}")
            finally:
                PENDING.pop(chat_id, None)
            return

        if ptype == "archive_encrypt_choice":
            bytes_archive = pending["bytes"]
            orig_name = pending.get("orig_name","archive.zip")
            # perform recursive encryption using chosen label
            try:
                out_bytes = process_archive_recursive_and_build(bytes_archive, action="encrypt", encrypt_choice_label=label)
                out_name = os.path.splitext(orig_name)[0] + "_encrypted.zip"
                await bot.send_document(chat_id, types.InputFile(BytesIO(out_bytes), filename=out_name))
                await cb.message.reply("Архив зашифрован.")
            except Exception as e:
                await cb.message.reply(f"Ошибка при шифровании архива: {e}")
            finally:
                PENDING.pop(chat_id, None)
            return

    # fallback
    await cb.message.reply("Неизвестное действие.")

# start polling
if __name__ == "__main__":
    executor.start_polling(dp, skip_updates=True)