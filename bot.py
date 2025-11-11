# bot.py
import os
import logging
import base64
import re
import json
import tempfile
import shutil
from io import BytesIO
from zipfile import ZipFile, ZIP_DEFLATED
from pathlib import Path

import aiohttp
import UnityPy
from lxml import etree
from dotenv import load_dotenv

from aiogram import Bot, Dispatcher, types
from aiogram.types import ContentType, InlineKeyboardButton, InlineKeyboardMarkup
from aiogram.utils import executor

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_env_clean(key: str, default=""):
    val = os.getenv(key, default)
    if val is None:
        return default
    if isinstance(val, str):
        # strip spaces/newlines and remove BOM
        return val.strip().replace("\ufeff", "")
    return val

BOT_TOKEN = get_env_clean("BOT_TOKEN")
if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN not found in environment")

def load_key_pairs(prefix: str):
    pairs = []
    idx = 1
    while True:
        key_name = f"{prefix}_KEY_HEX" if idx == 1 else f"{prefix}_KEY_HEX_{idx}"
        iv_name = f"{prefix}_IV_HEX" if idx == 1 else f"{prefix}_IV_HEX_{idx}"
        key_hex = get_env_clean(key_name, "")
        iv_hex = get_env_clean(iv_name, "")
        if not key_hex or not iv_hex:
            break
        try:
            key_bytes = bytes.fromhex(key_hex)
            iv_bytes = bytes.fromhex(iv_hex)
            pairs.append((key_name, key_bytes, iv_bytes))
        except Exception as e:
            logger.warning("Invalid hex for %s/%s: %s", key_name, iv_name, e)
        idx += 1
    return pairs

TEXT_KEYS = load_key_pairs("AES_TEXT")       # AES-256-CBC pairs (label, key, iv)
ARCHIVE_KEYS = load_key_pairs("AES_ARCHIVE") # AES-128-CBC pairs (label, key, iv)

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher(bot)

# small in-memory pending store: chat_id -> {type, data, token}
PENDING = {}

def aes_cbc_decrypt_raw(data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(data), AES.block_size)

def aes_cbc_encrypt_raw(data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(data, AES.block_size))

def try_decrypt_with_keylist(data: bytes, keylist):
    last_exc = None
    for label, key, iv in keylist:
        try:
            dec = aes_cbc_decrypt_raw(data, key, iv)
            return label, dec
        except Exception as e:
            last_exc = e
            continue
    raise RuntimeError("No key succeeded") from last_exc

def try_decrypt_archive_inner(enc_bytes: bytes):
    # ARCHIVE_KEYS expected to be AES-128 keys (16 bytes)
    return try_decrypt_with_keylist(enc_bytes, ARCHIVE_KEYS)

def try_decrypt_text_base64(b64data: bytes):
    # try each TEXT key (AES-256)
    return try_decrypt_with_keylist(b64data, TEXT_KEYS)

def detect_and_pretty_json_or_xml(data_bytes: bytes):
    # JSON
    try:
        obj = json.loads(data_bytes.decode("utf-8"))
        pretty = json.dumps(obj, ensure_ascii=False, indent=2)
        return ".json", pretty.encode("utf-8")
    except Exception:
        pass
    # XML via lxml
    try:
        parser = etree.XMLParser(remove_blank_text=True, recover=True)
        root = etree.fromstring(data_bytes, parser=parser)
        pretty = etree.tostring(root, pretty_print=True, encoding="utf-8")
        return ".xml", pretty
    except Exception:
        pass
    # fallback binary/text
    return ".bin", data_bytes

def process_encrypted_text_bytes(raw_bytes: bytes):
    # raw_bytes likely is base64-encoded AES-256-CBC
    s = raw_bytes.decode("utf-8", errors="ignore").strip()
    try:
        b64 = base64.b64decode(s)
    except Exception as e:
        raise ValueError("Not base64 or corrupted") from e
    label, dec = try_decrypt_text_base64(b64)
    ext, pretty = detect_and_pretty_json_or_xml(dec)
    if ext == ".bin":
        # maybe it's plain text
        try:
            return ".txt", dec
        except Exception:
            return ".bin", dec
    return ext, pretty

def process_encrypted_archive_bytes(zip_bytes: bytes):
    # look for first candidate file inside zip to decrypt with ARCHIVE_KEYS
    with ZipFile(BytesIO(zip_bytes)) as z:
        candidate = None
        for name in z.namelist():
            low = name.lower()
            if low.endswith(("/",)):
                continue
            if low.endswith((".sig", ".rsa", ".pem", ".zip.sha")):
                continue
            candidate = name
            break
        if not candidate:
            raise RuntimeError("No candidate file found inside zip")
        enc_bytes = z.read(candidate)
        label, dec = try_decrypt_archive_inner(enc_bytes)
        out_name = os.path.basename(candidate)
        if out_name.endswith(".enc"):
            out_name = out_name[:-4]
        return out_name, dec

def extract_unity_bundle_to_zip(bundle_bytes: bytes, bundle_name: str):
    tmpdir = tempfile.mkdtemp()
    try:
        env = UnityPy.load(bundle_bytes)
        out_paths = []
        for obj in env.objects:
            try:
                data = obj.read()
            except Exception:
                continue
            tname = getattr(data, "name", None) or getattr(data, "sourceFileName", None) or obj.path
            if obj.type == "Texture2D" or getattr(data, "image", None) is not None:
                img = data.image
                fname = f"{tname}.png" if not str(tname).lower().endswith(".png") else str(tname)
                p = os.path.join(tmpdir, fname)
                img.save(p)
                out_paths.append((p, fname))
            elif obj.type == "TextAsset" or hasattr(data, "script"):
                # Text asset
                text = getattr(data, "text", None)
                if text is None:
                    try:
                        text = data.script
                    except Exception:
                        text = None
                if text is not None:
                    fname = f"{tname}.txt"
                    p = os.path.join(tmpdir, fname)
                    with open(p, "w", encoding="utf-8") as f:
                        f.write(str(text))
                    out_paths.append((p, fname))
            else:
                # try to dump raw
                try:
                    raw = data.read() if hasattr(data, "read") else None
                except Exception:
                    raw = None
                if raw:
                    fname = f"{tname}.bin"
                    p = os.path.join(tmpdir, fname)
                    with open(p, "wb") as f:
                        f.write(raw)
                    out_paths.append((p, fname))
        # make zip
        out_io = BytesIO()
        with ZipFile(out_io, "w", ZIP_DEFLATED) as zout:
            for path, arcname in out_paths:
                zout.write(path, arcname)
        return f"{os.path.splitext(bundle_name)[0]}.zip", out_io.getvalue()
    finally:
        shutil.rmtree(tmpdir)

def process_archive_recursive_and_build(zip_bytes: bytes, action: str, encrypt_text_key_label: str = None):
    tmpdir = tempfile.mkdtemp()
    try:
        with ZipFile(BytesIO(zip_bytes)) as zin:
            zin.extractall(tmpdir)
        # walk
        for root, dirs, files in os.walk(tmpdir):
            for fname in list(files):
                fpath = os.path.join(root, fname)
                rel = os.path.relpath(fpath, tmpdir)
                lower = fname.lower()
                # nested zip handling
                if lower.endswith(".zip"):
                    with open(fpath, "rb") as rf:
                        nested = rf.read()
                    if action == "decrypt":
                        try:
                            # try to decrypt inner file(s) inside nested zip
                            out_name, out_bytes = process_encrypted_archive_bytes(nested)
                            # replace nested zip with new zip containing decrypted file
                            newzip = BytesIO()
                            with ZipFile(newzip, "w", ZIP_DEFLATED) as wz:
                                wz.writestr(out_name, out_bytes)
                            with open(fpath, "wb") as wf:
                                wf.write(newzip.getvalue())
                        except Exception:
                            # leave as is if cannot decrypt
                            pass
                    elif action == "encrypt":
                        # skip nested encryption for simplicity
                        pass
                    continue

                # text files detection
                try:
                    with open(fpath, "rb") as rf:
                        content = rf.read()
                except Exception:
                    continue

                if action == "decrypt":
                    # try base64 text -> decrypt -> pretty
                    try:
                        ext, pretty = process_encrypted_text_bytes(content)
                        newname = os.path.splitext(fpath)[0] + ext
                        with open(newname, "wb") as wf:
                            wf.write(pretty)
                        if newname != fpath:
                            os.remove(fpath)
                    except Exception:
                        # try .enc files -> decrypt with archive keys
                        if fname.endswith(".enc"):
                            try:
                                label, dec = try_decrypt_archive_inner(content)
                                outname = os.path.splitext(fpath)[0]  # remove .enc
                                with open(outname, "wb") as wf:
                                    wf.write(dec)
                                os.remove(fpath)
                            except Exception:
                                pass
                        else:
                            pass
                elif action == "encrypt":
                    # for text files: try minify JSON/XML then encrypt with chosen key
                    if encrypt_text_key_label is None:
                        continue
                    # find key by label
                    chosen = None
                    for lab, key, iv in TEXT_KEYS:
                        if lab == encrypt_text_key_label:
                            chosen = (key, iv)
                            break
                    if not chosen:
                        continue
                    key, iv = chosen
                    # try JSON
                    try:
                        txt = content.decode("utf-8")
                        obj = json.loads(txt)
                        minified = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
                        cipher = aes_cbc_encrypt_raw(minified, key, iv)
                        b64 = base64.b64encode(cipher)
                        with open(fpath, "wb") as wf:
                            wf.write(b64)
                        continue
                    except Exception:
                        pass
                    # try XML
                    try:
                        parser = etree.XMLParser(remove_blank_text=True, recover=True)
                        root = etree.fromstring(content, parser=parser)
                        minified = etree.tostring(root, pretty_print=False, encoding="utf-8")
                        cipher = aes_cbc_encrypt_raw(minified, key, iv)
                        b64 = base64.b64encode(cipher)
                        with open(fpath, "wb") as wf:
                            wf.write(b64)
                        continue
                    except Exception:
                        pass
                    # if file is binary or not json/xml - skip

        # rezip
        out_io = BytesIO()
        with ZipFile(out_io, "w", ZIP_DEFLATED) as zout:
            for root, dirs, files in os.walk(tmpdir):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    arcname = os.path.relpath(fpath, tmpdir)
                    zout.write(fpath, arcname)
        return out_io.getvalue()
    finally:
        shutil.rmtree(tmpdir)

# --- keyboards and helpers ---
def kb_confirm_link():
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(InlineKeyboardButton("🔓 Расшифровать", callback_data="A:DL:DEC"),
           InlineKeyboardButton("❌ Отмена", callback_data="A:DL:CANCEL"))
    return kb

def kb_archive_choice():
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(InlineKeyboardButton("🔓 Расшифровать архив (всю структуру)", callback_data="A:ZIP:DEC"),
           InlineKeyboardButton("🔒 Зашифровать архив", callback_data="A:ZIP:ENC"),
           InlineKeyboardButton("❌ Отмена", callback_data="A:ZIP:CANCEL"))
    return kb

def kb_single_choice():
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(InlineKeyboardButton("🔓 Расшифровать", callback_data="A:SINGLE:DEC"),
           InlineKeyboardButton("🔒 Зашифровать", callback_data="A:SINGLE:ENC"),
           InlineKeyboardButton("❌ Отмена", callback_data="A:SINGLE:CANCEL"))
    return kb

def kb_key_choice_for_text():
    kb = InlineKeyboardMarkup(row_width=1)
    for idx, (label, key, iv) in enumerate(TEXT_KEYS, start=1):
        kb.add(InlineKeyboardButton(f"Ключ {idx} ({label})", callback_data=f"KEY:T:{idx}"))
    kb.add(InlineKeyboardButton("Отмена", callback_data="KEY:CANCEL"))
    return kb

# --- Handlers ---
@dp.message_handler(commands=["start", "help"])
async def cmd_start(message: types.Message):
    await message.reply("Привет! Пришли файл/архив или ссылку. Буду предлагать варианты действий (расшифровать/зашифровать).")

@dp.message_handler(commands=["changes"])
async def cmd_changes(message: types.Message):
    changes = (
        "📝 Последние изменения:\n"
        "* support UnityPy extraction\n"
        "* recursive archive decrypt/encrypt\n"
        "* keys via .env\n"
    )
    await message.reply(changes)

@dp.message_handler(content_types=ContentType.DOCUMENT)
async def handle_document(message: types.Message):
    doc = message.document
    filename = doc.file_name or "file"
    file_obj = await bot.get_file(doc.file_id)
    file_bytes = await bot.download_file(file_obj.file_path)
    data = file_bytes.read()
    lower = filename.lower()
    if lower.endswith((".unity3d", ".bundle", ".assets", ".ab", ".resS")):
        await message.reply("Принял Unity bundle — распаковать и отправить?", reply_markup=InlineKeyboardMarkup().add(
            InlineKeyboardButton("Да — распаковать", callback_data="U:EX:DO"),
            InlineKeyboardButton("Отмена", callback_data="U:EX:CANCEL")
        ))
        # store
        PENDING[message.chat.id] = {"type": "unity_bundle", "bytes": data, "name": filename}
        return

    if lower.endswith(".zip"):
        await message.reply("Принят ZIP. Что делаем?", reply_markup=kb_archive_choice())
        PENDING[message.chat.id] = {"type": "archive_uploaded", "bytes": data, "name": filename}
        return

    # else single file
    PENDING[message.chat.id] = {"type": "single_file", "bytes": data, "name": filename}
    await message.reply("Выберите действие для файла:", reply_markup=kb_single_choice())

@dp.message_handler(lambda message: re.search(r'https?://\S+', message.text or ""))
async def handle_link(message: types.Message):
    url = re.search(r'(https?://\S+)', message.text).group(1)
    await message.reply("Получаю мета-информацию...")
    try:
        async with aiohttp.ClientSession() as session:
            async with session.head(url, timeout=15) as resp:
                headers = resp.headers
            size = headers.get("Content-Length", "неизвестно")
            last_mod = headers.get("Last-Modified") or headers.get("Date") or "неизвестно"
    except Exception:
        size = "неизвестно"
        last_mod = "неизвестно"
    text = f"Файл: {os.path.basename(url)}\nРазмер (байт): {size}\nПоследнее изменение: {last_mod}\n\nСкачать и обработать?"
    await message.reply(text, reply_markup=kb_confirm_link())
    PENDING[message.chat.id] = {"type": "link_pending", "url": url, "name": os.path.basename(url)}

@dp.callback_query_handler(lambda c: True)
async def cb_handler(cb: types.CallbackQuery):
    data = cb.data or ""
    chat_id = cb.message.chat.id
    await cb.answer()  # ack
    # link confirm
    if data == "A:DL:DEC":
        pending = PENDING.get(chat_id)
        if not pending or pending.get("type") != "link_pending":
            await cb.message.reply("Нет данных для загрузки.")
            return
        url = pending["url"]
        await cb.message.reply("Скачиваю и обрабатываю ссылку...")
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=60) as resp:
                    if resp.status != 200:
                        raise RuntimeError(f"HTTP {resp.status}")
                    content = await resp.read()
            name = pending.get("name") or os.path.basename(url)
            lower = name.lower()
            if lower.endswith(".zip") or url.lower().endswith(".zip") or url.lower().endswith(".zip.enc"):
                # treat as zip archive: process recursive decrypt
                out_bytes = process_archive_recursive_and_build(content, action="decrypt")
                out_name = name  # keep same name
                await bot.send_document(chat_id, types.InputFile(BytesIO(out_bytes), filename=out_name))
            elif lower.endswith((".unity3d", ".bundle", ".assets", ".ab", ".ress")):
                # Unity bundle: extract
                out_name, outb = extract_unity_bundle_to_zip(content, name)
                await bot.send_document(chat_id, types.InputFile(BytesIO(outb), filename=out_name))
            else:
                # try single decrypt
                try:
                    ext, outb = process_encrypted_text_bytes(content)
                    out_name = os.path.splitext(name)[0] + ext
                    await bot.send_document(chat_id, types.InputFile(BytesIO(outb), filename=out_name))
                except Exception:
                    # try archive inner
                    try:
                        out_name, outb = process_encrypted_archive_bytes(content)
                        await bot.send_document(chat_id, types.InputFile(BytesIO(outb), filename=out_name))
                    except Exception as e:
                        raise
            await cb.message.reply("Готово.")
        except Exception as e:
            await cb.message.reply(f"Ошибка при обработке ссылки: {e}")
        finally:
            PENDING.pop(chat_id, None)
        return

    if data == "A:DL:CANCEL":
        PENDING.pop(chat_id, None)
        await cb.message.reply("Отменено.")
        return

    # archive choices
    if data == "A:ZIP:DEC":
        pending = PENDING.get(chat_id)
        if not pending or pending.get("type") != "archive_uploaded":
            await cb.message.reply("Нет загруженного архива.")
            return
        await cb.message.reply("Начинаю рекурсивную расшифровку архива (включая подпапки)...")
        try:
            out_bytes = process_archive_recursive_and_build(pending["bytes"], action="decrypt")
            out_name = pending.get("name", "archive.zip")
            await bot.send_document(chat_id, types.InputFile(BytesIO(out_bytes), filename=out_name))
            await cb.message.reply("Готово.")
        except Exception as e:
            await cb.message.reply(f"Ошибка: {e}")
        finally:
            PENDING.pop(chat_id, None)
        return

    if data == "A:ZIP:ENC":
        pending = PENDING.get(chat_id)
        if not pending or pending.get("type") != "archive_uploaded":
            await cb.message.reply("Нет загруженного архива.")
            return
        if not TEXT_KEYS:
            await cb.message.reply("Нет текстовых ключей (AES_TEXT_*) в окружении.")
            return
        # ask which key
        PENDING[chat_id] = {"type": "archive_encrypt_choose", "bytes": pending["bytes"], "name": pending.get("name")}
        await cb.message.reply("Выберите текстовый ключ для шифрования JSON/XML в архиве:", reply_markup=kb_key_choice_for_text())
        return

    if data == "A:ZIP:CANCEL":
        PENDING.pop(chat_id, None)
        await cb.message.reply("Отменено.")
        return

    # single file actions
    if data == "A:SINGLE:DEC":
        pending = PENDING.get(chat_id)
        if not pending or pending.get("type") != "single_file":
            await cb.message.reply("Нет файла в очереди.")
            return
        await cb.message.reply("Попытка расшифровки файла...")
        try:
            name = pending["name"]
            b = pending["bytes"]
            lower = name.lower()
            if lower.endswith(".zip"):
                out_bytes = process_archive_recursive_and_build(b, action="decrypt")
                await bot.send_document(chat_id, types.InputFile(BytesIO(out_bytes), filename=name))
            else:
                try:
                    ext, outb = process_encrypted_text_bytes(b)
                    out_name = os.path.splitext(name)[0] + ext
                    await bot.send_document(chat_id, types.InputFile(BytesIO(outb), filename=out_name))
                except Exception:
                    # maybe it's archive-inner encrypted binary
                    try:
                        out_name, outb = process_encrypted_archive_bytes(b)
                        await bot.send_document(chat_id, types.InputFile(BytesIO(outb), filename=out_name))
                    except Exception as e:
                        raise e
            await cb.message.reply("Готово.")
        except Exception as e:
            await cb.message.reply(f"Ошибка: {e}")
        finally:
            PENDING.pop(chat_id, None)
        return

    if data == "A:SINGLE:ENC":
        pending = PENDING.get(chat_id)
        if not pending or pending.get("type") != "single_file":
            await cb.message.reply("Нет файла в очереди.")
            return
        if not TEXT_KEYS:
            await cb.message.reply("Нет текстовых ключей (AES_TEXT_*) в окружении.")
            return
        # ask which key
        PENDING[chat_id] = {"type": "single_encrypt_choose", "bytes": pending["bytes"], "name": pending.get("name")}
        await cb.message.reply("Выберите текстовый ключ для шифрования:", reply_markup=kb_key_choice_for_text())
        return

    if data == "A:SINGLE:CANCEL":
        PENDING.pop(chat_id, None)
        await cb.message.reply("Отменено.")
        return

    # Unity bundle callbacks
    if data == "U:EX:DO":
        pending = PENDING.get(chat_id)
        if not pending or pending.get("type") != "unity_bundle":
            await cb.message.reply("Нет bundle в очереди.")
            return
        await cb.message.reply("Распаковываю Unity bundle...")
        try:
            out_name, outb = extract_unity_bundle_to_zip(pending["bytes"], pending.get("name"))
            await bot.send_document(chat_id, types.InputFile(BytesIO(outb), filename=out_name))
            await cb.message.reply("Готово.")
        except Exception as e:
            await cb.message.reply(f"Ошибка: {e}")
        finally:
            PENDING.pop(chat_id, None)
        return

    if data == "U:EX:CANCEL":
        PENDING.pop(chat_id, None)
        await cb.message.reply("Отменено.")
        return

    # choosing text key callbacks: KEY:T:idx
    if data.startswith("KEY:T:"):
        parts = data.split(":")
        if len(parts) != 3:
            await cb.message.reply("Неправильный callback.")
            return
        try:
            idx = int(parts[2])
        except Exception:
            await cb.message.reply("Неправильный индекс ключа.")
            return
        if idx < 1 or idx > len(TEXT_KEYS):
            await cb.message.reply("Индекс ключа вне диапазона.")
            return
        label, key, iv = TEXT_KEYS[idx-1]
        pending = PENDING.get(chat_id)
        if not pending:
            await cb.message.reply("Нет задачи в очереди.")
            return
        ptype = pending.get("type")
        if ptype == "single_encrypt_choose":
            b = pending["bytes"]
            name = pending.get("name", "file")
            try:
                txt = b.decode("utf-8")
            except Exception:
                await cb.message.reply("Файл не является текстовым JSON/XML — шифрование пропущено.")
                PENDING.pop(chat_id, None)
                return
            # try JSON minify
            done = False
            try:
                obj = json.loads(txt)
                minified = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
                cipher = aes_cbc_encrypt_raw(minified, key, iv)
                b64 = base64.b64encode(cipher)
                out_name = os.path.splitext(name)[0] + ".enc.b64"
                await bot.send_document(chat_id, types.InputFile(BytesIO(b64), filename=out_name))
                await cb.message.reply("Файл зашифрован.")
                done = True
            except Exception:
                pass
            if not done:
                # try xml
                try:
                    parser = etree.XMLParser(remove_blank_text=True, recover=True)
                    root = etree.fromstring(txt.encode("utf-8"), parser=parser)
                    minified = etree.tostring(root, pretty_print=False, encoding="utf-8")
                    cipher = aes_cbc_encrypt_raw(minified, key, iv)
                    b64 = base64.b64encode(cipher)
                    out_name = os.path.splitext(name)[0] + ".enc.b64"
                    await bot.send_document(chat_id, types.InputFile(BytesIO(b64), filename=out_name))
                    await cb.message.reply("Файл зашифрован.")
                    done = True
                except Exception:
                    pass
            if not done:
                await cb.message.reply("Не удалось распознать JSON/XML — файл не зашифрован.")
            PENDING.pop(chat_id, None)
            return

        if ptype == "archive_encrypt_choose":
            bytes_archive = pending.get("bytes")
            name = pending.get("name", "archive.zip")
            try:
                out_bytes = process_archive_recursive_and_build(bytes_archive, action="encrypt", encrypt_text_key_label=label)
                out_name = name
                await bot.send_document(chat_id, types.InputFile(BytesIO(out_bytes), filename=out_name))
                await cb.message.reply("Архив зашифрован.")
            except Exception as e:
                await cb.message.reply(f"Ошибка при шифровании архива: {e}")
            finally:
                PENDING.pop(chat_id, None)
            return

    if data == "KEY:CANCEL":
        PENDING.pop(chat_id, None)
        await cb.message.reply("Отменено.")
        return

    # fallback
    await cb.message.reply("Неопознанное действие.")

if __name__ == "__main__":
    executor.start_polling(dp, skip_updates=True)