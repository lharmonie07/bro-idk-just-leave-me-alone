import os
import logging
import base64
import json
import tempfile
import shutil
from io import BytesIO
from zipfile import ZipFile, ZIP_DEFLATED
from pathlib import Path
import re

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
    v = os.getenv(key, default)
    if v is None:
        return default
    return v.strip().replace("\ufeff", "")

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
            pairs.append((key_name, bytes.fromhex(key_hex), bytes.fromhex(iv_hex)))
        except Exception:
            logger.warning("Invalid hex for %s/%s", key_name, iv_name)
        idx += 1
    return pairs

TEXT_KEYS = load_key_pairs("AES_TEXT")
ARCHIVE_KEYS = load_key_pairs("AES_ARCHIVE")

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher(bot)

PENDING = {}  # chat_id -> {"mode": ..., ...}

def aes_cbc_decrypt_raw(data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(data), AES.block_size)

def aes_cbc_encrypt_raw(data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(data, AES.block_size))

def try_decrypt_with_list(data: bytes, pairs):
    last = None
    for label, key, iv in pairs:
        try:
            return label, aes_cbc_decrypt_raw(data, key, iv)
        except Exception as e:
            last = e
            continue
    raise RuntimeError("No key succeeded") from last

def detect_json_or_xml_pretty(b: bytes):
    try:
        obj = json.loads(b.decode("utf-8"))
        return ".json", json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")
    except Exception:
        pass
    try:
        parser = etree.XMLParser(remove_blank_text=True, recover=True)
        root = etree.fromstring(b, parser=parser)
        return ".xml", etree.tostring(root, pretty_print=True, encoding="utf-8")
    except Exception:
        pass
    try:
        return ".txt", b
    except Exception:
        return ".bin", b

def process_encrypted_text_bytes(raw_bytes: bytes):
    s = raw_bytes.decode("utf-8", errors="ignore").strip()
    try:
        b64 = base64.b64decode(s)
    except Exception:
        raise ValueError("Not base64")
    label, dec = try_decrypt_with_list(b64, TEXT_KEYS)
    ext, pretty = detect_json_or_xml_pretty(dec)
    return ext, pretty, label

def process_encrypted_archive_bytes(zip_bytes: bytes):
    with ZipFile(BytesIO(zip_bytes)) as z:
        candidate = None
        for name in z.namelist():
            low = name.lower()
            if name.endswith("/") or low.endswith((".sig", ".rsa", ".pem", ".zip.sha")):
                continue
            candidate = name
            break
        if not candidate:
            raise RuntimeError("No candidate file in zip")
        enc = z.read(candidate)
        label, dec = try_decrypt_with_list(enc, ARCHIVE_KEYS)
        out_name = Path(candidate).name
        if out_name.endswith(".enc"):
            out_name = out_name[:-4]
        return out_name, dec, label

def extract_unity_textassets_to_zip(bundle_bytes: bytes, bundle_name: str):
    tmp = tempfile.mkdtemp()
    try:
        env = UnityPy.load(bundle_bytes)
        saved = []
        for obj in env.objects:
            if obj.type.name == "TextAsset":
                try:
                    data = obj.read()
                    name = getattr(data, "name", None) or obj.path or "textasset"
                    text = getattr(data, "text", None)
                    if text is None:
                        # some TextAsset stores bytes in 'script' or 'm_Script' or raw
                        text = getattr(data, "m_Script", None) or getattr(data, "bytes", None)
                        if isinstance(text, bytes):
                            try:
                                text = text.decode("utf-8", errors="ignore")
                            except Exception:
                                text = None
                    if text is not None:
                        fname = f"{name}.txt"
                        p = Path(tmp) / fname
                        p.write_text(str(text), encoding="utf-8", errors="ignore")
                        saved.append((str(p), fname))
                except Exception:
                    continue
        out = BytesIO()
        with ZipFile(out, "w", ZIP_DEFLATED) as zout:
            for p, arc in saved:
                zout.write(p, arc)
        return f"{Path(bundle_name).stem}_textassets.zip", out.getvalue()
    finally:
        shutil.rmtree(tmp)

def process_archive_recursive_and_build(zip_bytes: bytes, action: str, encrypt_text_key_label: str = None):
    tmp = tempfile.mkdtemp()
    try:
        with ZipFile(BytesIO(zip_bytes)) as zin:
            zin.extractall(tmp)
        for root, _, files in os.walk(tmp):
            for fname in list(files):
                fpath = os.path.join(root, fname)
                lower = fname.lower()
                with open(fpath, "rb") as rf:
                    content = rf.read()
                if lower.endswith(".zip"):
                    if action == "decrypt":
                        try:
                            out_name, out_bytes, _ = process_encrypted_archive_bytes(content)
                            newzip = BytesIO()
                            with ZipFile(newzip, "w", ZIP_DEFLATED) as wz:
                                wz.writestr(out_name, out_bytes)
                            with open(fpath, "wb") as wf:
                                wf.write(newzip.getvalue())
                        except Exception:
                            pass
                    continue
                if action == "decrypt":
                    try:
                        ext, pretty, _ = process_encrypted_text_bytes(content)
                        newpath = os.path.splitext(fpath)[0] + ext
                        with open(newpath, "wb") as wf:
                            wf.write(pretty)
                        if newpath != fpath:
                            os.remove(fpath)
                        continue
                    except Exception:
                        if fname.endswith(".enc"):
                            try:
                                label, dec = try_decrypt_with_list(content, ARCHIVE_KEYS)
                                outp = os.path.splitext(fpath)[0]
                                with open(outp, "wb") as wf:
                                    wf.write(dec)
                                os.remove(fpath)
                                continue
                            except Exception:
                                pass
                        pass
                elif action == "encrypt":
                    if encrypt_text_key_label is None:
                        continue
                    chosen = None
                    for lab, key, iv in TEXT_KEYS:
                        if lab == encrypt_text_key_label:
                            chosen = (key, iv)
                            break
                    if not chosen:
                        continue
                    try:
                        txt = content.decode("utf-8")
                    except Exception:
                        continue
                    done = False
                    try:
                        obj = json.loads(txt)
                        minified = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
                        cipher = aes_cbc_encrypt_raw(minified, chosen[0], chosen[1])
                        with open(fpath, "wb") as wf:
                            wf.write(base64.b64encode(cipher))
                        done = True
                    except Exception:
                        pass
                    if done:
                        continue
                    try:
                        parser = etree.XMLParser(remove_blank_text=True, recover=True)
                        root = etree.fromstring(txt.encode("utf-8"), parser=parser)
                        minified = etree.tostring(root, pretty_print=False, encoding="utf-8")
                        cipher = aes_cbc_encrypt_raw(minified, chosen[0], chosen[1])
                        with open(fpath, "wb") as wf:
                            wf.write(base64.b64encode(cipher))
                    except Exception:
                        pass
        out = BytesIO()
        with ZipFile(out, "w", ZIP_DEFLATED) as zout:
            for root, _, files in os.walk(tmp):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    arcname = os.path.relpath(fpath, tmp)
                    zout.write(fpath, arcname)
        return out.getvalue()
    finally:
        shutil.rmtree(tmp)

# Keyboards
def main_menu_kb():
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(
        InlineKeyboardButton("🔓 Расшифровать", callback_data="MODE_DEC"),
        InlineKeyboardButton("🔒 Зашифровать", callback_data="MODE_ENC"),
    )
    kb.add(
        InlineKeyboardButton("📦 Архив (rec)", callback_data="MODE_ARCH"),
        InlineKeyboardButton("🧩 Unity bundle", callback_data="MODE_BND"),
    )
    kb.add(InlineKeyboardButton("ℹ️ Changes", callback_data="MODE_CHG"))
    return kb

def confirm_link_kb():
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(InlineKeyboardButton("🔓 Расшифровать", callback_data="LINK_DEC"),
           InlineKeyboardButton("❌ Отмена", callback_data="CANCEL"))
    return kb

def archive_choice_kb():
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(InlineKeyboardButton("🔓 Расшифровать (всю структуру)", callback_data="ARCH_DEC"),
           InlineKeyboardButton("🔒 Зашифровать (всю структуру)", callback_data="ARCH_ENC"))
    kb.add(InlineKeyboardButton("❌ Отмена", callback_data="CANCEL"))
    return kb

def kb_choose_text_key():
    kb = InlineKeyboardMarkup(row_width=1)
    for idx, (label, key, iv) in enumerate(TEXT_KEYS, start=1):
        kb.add(InlineKeyboardButton(f"Key {idx}", callback_data=f"KEY_T_{idx}"))
    kb.add(InlineKeyboardButton("Отмена", callback_data="CANCEL"))
    return kb

# Handlers
@dp.message_handler(commands=["start", "help"])
async def cmd_start(message: types.Message):
    await message.reply("Главное меню:", reply_markup=main_menu_kb())

@dp.callback_query_handler(lambda c: c.data == "MODE_CHG")
async def show_changes(cb: types.CallbackQuery):
    await cb.answer()
    await cb.message.reply("📝 Последние изменения:\n• TextAsset extraction only for Unity bundles\n• Commands via buttons\n• Keys from .env")
    await cb.message.reply("Возвращаю в главное меню.", reply_markup=main_menu_kb())

@dp.callback_query_handler(lambda c: c.data == "MODE_DEC")
async def mode_dec(cb: types.CallbackQuery):
    await cb.answer()
    PENDING[cb.message.chat.id] = {"mode": "decrypt_wait"}
    await cb.message.reply("Режим: Расшифровать. Пришли файл (.zip/.enc/.txt/unity) или ссылку.", reply_markup=None)

@dp.callback_query_handler(lambda c: c.data == "MODE_ENC")
async def mode_enc(cb: types.CallbackQuery):
    await cb.answer()
    PENDING[cb.message.chat.id] = {"mode": "encrypt_wait"}
    await cb.message.reply("Режим: Зашифровать. Пришли файл (.json/.xml/.txt) или ссылку.", reply_markup=None)

@dp.callback_query_handler(lambda c: c.data == "MODE_ARCH")
async def mode_arch(cb: types.CallbackQuery):
    await cb.answer()
    PENDING[cb.message.chat.id] = {"mode": "archive_wait"}
    await cb.message.reply("Режим: Архив (рекурсив). Пришли ZIP или ссылку на ZIP.", reply_markup=None)

@dp.callback_query_handler(lambda c: c.data == "MODE_BND")
async def mode_bnd(cb: types.CallbackQuery):
    await cb.answer()
    PENDING[cb.message.chat.id] = {"mode": "bundle_wait"}
    await cb.message.reply("Режим: Unity bundle. Пришли bundle (можно без расширения) или ссылку.", reply_markup=None)

@dp.callback_query_handler(lambda c: c.data == "CANCEL")
async def cb_cancel(cb: types.CallbackQuery):
    await cb.answer()
    PENDING.pop(cb.message.chat.id, None)
    await cb.message.reply("Отменено. Возвращаю в главное меню.", reply_markup=main_menu_kb())

@dp.message_handler(lambda message: re.search(r'https?://\S+', message.text or ""))
async def handle_link(message: types.Message):
    chat_id = message.chat.id
    pending = PENDING.get(chat_id)
    url = re.search(r'(https?://\S+)', message.text).group(1)
    await message.reply("Получаю мета-информацию...")
    try:
        async with aiohttp.ClientSession() as session:
            async with session.head(url, timeout=15) as resp:
                headers = resp.headers
            size = headers.get("Content-Length", "неизвестно")
            lm = headers.get("Last-Modified") or headers.get("Date") or "неизвестно"
    except Exception:
        size = "неизвестно"
        lm = "неизвестно"
    await message.reply(f"Файл: {os.path.basename(url)}\nРазмер: {size}\nПоследнее изменение: {lm}",
                        reply_markup=confirm_link_kb())
    PENDING[chat_id] = {"mode": "link_pending", "url": url, "prev": pending}

@dp.message_handler(content_types=ContentType.DOCUMENT)
async def handle_document(message: types.Message):
    chat_id = message.chat.id
    pending = PENDING.get(chat_id)
    doc = message.document
    filename = doc.file_name or "file"
    file_obj = await bot.get_file(doc.file_id)
    file_bytes = await bot.download_file(file_obj.file_path)
    data = file_bytes.read()
    await message.reply(f"Файл получен: {filename}")
    await handle_incoming_content(chat_id, filename, data)

@dp.message_handler(content_types=ContentType.ANY)
async def handle_text_or_other(message: types.Message):
    # ignore non-file non-link messages
    pass

async def handle_incoming_content(chat_id: int, filename: str, data: bytes):
    pending = PENDING.get(chat_id, {})
    mode = pending.get("mode")
    try:
        if mode == "decrypt_wait":
            await do_decrypt(chat_id, filename, data)
        elif mode == "encrypt_wait":
            await do_encrypt(chat_id, filename, data)
        elif mode == "archive_wait":
            if filename.lower().endswith(".zip"):
                await do_archive_process(chat_id, filename, data, action="decrypt")  # default decrypt
            else:
                # try treat as zip anyway by content
                try:
                    with ZipFile(BytesIO(data)) as _:
                        await do_archive_process(chat_id, filename, data, action="decrypt")
                    return
                except Exception:
                    await bot.send_message(chat_id, "Файл не распознан как ZIP.")
        elif mode == "bundle_wait":
            # accept even without extension: try to treat as Unity bundle
            try:
                out_name, outb = extract_unity_textassets_to_zip(data, filename)
                await bot.send_document(chat_id, types.InputFile(BytesIO(outb), filename=out_name))
            except Exception as e:
                await bot.send_message(chat_id, f"Ошибка распаковки Unity bundle: {e}")
        elif mode == "link_pending":
            await bot.send_message(chat_id, "Сначала нажмите кнопку 'Расшифровать' или 'Отмена'.")
        else:
            await bot.send_message(chat_id, "Сначала выберите режим в главном меню.", reply_markup=main_menu_kb())
    except Exception as e:
        await bot.send_message(chat_id, f"Ошибка: {e}")
    finally:
        PENDING.pop(chat_id, None)
        await bot.send_message(chat_id, "Возврат в главное меню.", reply_markup=main_menu_kb())

@dp.callback_query_handler(lambda c: c.data in ("LINK_DEC", "ARCH_DEC", "ARCH_ENC"))
async def cb_short_actions(cb: types.CallbackQuery):
    await cb.answer()
    chat_id = cb.message.chat.id
    data = cb.data
    pending = PENDING.get(chat_id)
    if not pending:
        await cb.message.reply("Нет задачи в очереди.")
        return
    if data == "LINK_DEC" and pending.get("mode") == "link_pending":
        url = pending.get("url")
        await cb.message.reply("Скачиваю ссылку и расшифровываю...")
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=60) as resp:
                    if resp.status != 200:
                        raise RuntimeError(f"HTTP {resp.status}")
                    content = await resp.read()
            name = pending.get("name") or os.path.basename(url)
            lower = name.lower()
            if lower.endswith(".zip"):
                out_bytes = process_archive_recursive_and_build(content, action="decrypt")
                await bot.send_document(chat_id, types.InputFile(BytesIO(out_bytes), filename=name))
            elif any(lower.endswith(ext) for ext in (".unity3d", ".bundle", ".assets", ".ab", ".ress")):
                out_name, outb = extract_unity_textassets_to_zip(content, name)
                await bot.send_document(chat_id, types.InputFile(BytesIO(outb), filename=out_name))
            else:
                try:
                    ext, outb, _ = process_encrypted_text_bytes(content)
                    out_name = Path(name).stem + ext
                    await bot.send_document(chat_id, types.InputFile(BytesIO(outb), filename=out_name))
                except Exception:
                    try:
                        out_name, outb, _ = process_encrypted_archive_bytes(content)
                        await bot.send_document(chat_id, types.InputFile(BytesIO(outb), filename=out_name))
                    except Exception as e:
                        raise e
            await cb.message.reply("Готово.")
        except Exception as e:
            await cb.message.reply(f"Ошибка при обработке ссылки: {e}")
        finally:
            PENDING.pop(chat_id, None)
            await cb.message.reply("Возврат в главное меню.", reply_markup=main_menu_kb())
        return

    if data in ("ARCH_DEC", "ARCH_ENC") and pending.get("mode") == "link_pending":
        url = pending.get("url")
        await cb.message.reply("Скачиваю архив...")
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=60) as resp:
                    if resp.status != 200:
                        raise RuntimeError(f"HTTP {resp.status}")
                    content = await resp.read()
            if data == "ARCH_DEC":
                out_bytes = process_archive_recursive_and_build(content, action="decrypt")
                await bot.send_document(chat_id, types.InputFile(BytesIO(out_bytes), filename=pending.get("name") or "archive.zip"))
            else:
                if not TEXT_KEYS:
                    await cb.message.reply("Нет текстовых ключей в окружении.")
                else:
                    PENDING[chat_id] = {"mode": "archive_encrypt_choose", "bytes": content, "name": pending.get("name")}
                    await cb.message.reply("Выберите текстовый ключ для шифрования:", reply_markup=kb_choose_text_key())
        except Exception as e:
            await cb.message.reply(f"Ошибка: {e}")
        finally:
            PENDING.pop(chat_id, None)
        return

@dp.callback_query_handler(lambda c: c.data and c.data.startswith("KEY_T_"))
async def cb_choose_key(cb: types.CallbackQuery):
    await cb.answer()
    chat_id = cb.message.chat.id
    idx = int(cb.data.split("_")[-1]) - 1
    if idx < 0 or idx >= len(TEXT_KEYS):
        await cb.message.reply("Неверный ключ.")
        return
    label, key, iv = TEXT_KEYS[idx]
    pending = PENDING.get(chat_id)
    if not pending:
        await cb.message.reply("Нет задачи.")
        return
    ptype = pending.get("mode")
    if ptype == "archive_encrypt_choose":
        try:
            out_bytes = process_archive_recursive_and_build(pending["bytes"], action="encrypt", encrypt_text_key_label=label)
            await bot.send_document(chat_id, types.InputFile(BytesIO(out_bytes), filename=pending.get("name") or "archive.zip"))
            await cb.message.reply("Архив зашифрован.")
        except Exception as e:
            await cb.message.reply(f"Ошибка при шифровании архива: {e}")
        finally:
            PENDING.pop(chat_id, None)
            await cb.message.reply("Возврат в главное меню.", reply_markup=main_menu_kb())
        return
    if ptype == "single_encrypt_choose":
        try:
            b = pending["bytes"]
            name = pending.get("name", "file")
            txt = b.decode("utf-8")
            done = False
            try:
                obj = json.loads(txt)
                minified = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
                cipher = aes_cbc_encrypt_raw(minified, key, iv)
                out = base64.b64encode(cipher)
                await bot.send_document(chat_id, types.InputFile(BytesIO(out), filename=Path(name).stem + ".enc.b64"))
                await cb.message.reply("Файл зашифрован.")
                done = True
            except Exception:
                pass
            if not done:
                try:
                    parser = etree.XMLParser(remove_blank_text=True, recover=True)
                    root = etree.fromstring(txt.encode("utf-8"), parser=parser)
                    minified = etree.tostring(root, pretty_print=False, encoding="utf-8")
                    cipher = aes_cbc_encrypt_raw(minified, key, iv)
                    out = base64.b64encode(cipher)
                    await bot.send_document(chat_id, types.InputFile(BytesIO(out), filename=Path(name).stem + ".enc.b64"))
                    await cb.message.reply("Файл зашифрован.")
                    done = True
                except Exception:
                    pass
            if not done:
                await cb.message.reply("Не удалось распознать JSON/XML — шифрование не выполнено.")
        except Exception as e:
            await cb.message.reply(f"Ошибка: {e}")
        finally:
            PENDING.pop(chat_id, None)
            await cb.message.reply("Возврат в главное меню.", reply_markup=main_menu_kb())
        return

@dp.callback_query_handler(lambda c: c.data and c.data.startswith("KEY_T_"))
async def cb_choose_key(cb: types.CallbackQuery):
    await cb.answer()
    chat_id = cb.message.chat.id
    idx = int(cb.data.split("_")[-1]) - 1
    if idx < 0 or idx >= len(TEXT_KEYS):
        await cb.message.reply("Неверный ключ.")
        return
    label, key, iv = TEXT_KEYS[idx]
    pending = PENDING.get(chat_id)
    if not pending:
        await cb.message.reply("Нет задачи.")
        return
    ptype = pending.get("mode")
    if ptype == "archive_encrypt_choose":
        try:
            out_bytes = process_archive_recursive_and_build(pending["bytes"], action="encrypt", encrypt_text_key_label=label)
            await bot.send_document(chat_id, types.InputFile(BytesIO(out_bytes), filename=pending.get("name") or "archive.zip"))
            await cb.message.reply("Архив зашифрован.")
        except Exception as e:
            await cb.message.reply(f"Ошибка при шифровании архива: {e}")
        finally:
            PENDING.pop(chat_id, None)
            await cb.message.reply("Возврат в главное меню.", reply_markup=main_menu_kb())
        return
    if ptype == "single_encrypt_choose":
        try:
            b = pending["bytes"]
            name = pending.get("name", "file")
            txt = b.decode("utf-8")
            done = False
            try:
                obj = json.loads(txt)
                minified = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
                cipher = aes_cbc_encrypt_raw(minified, key, iv)
                out = base64.b64encode(cipher)
                await bot.send_document(chat_id, types.InputFile(BytesIO(out), filename=Path(name).stem + ".enc.b64"))
                await cb.message.reply("Файл зашифрован.")
                done = True
            except Exception:
                pass
            if not done:
                try:
                    parser = etree.XMLParser(remove_blank_text=True, recover=True)
                    root = etree.fromstring(txt.encode("utf-8"), parser=parser)
                    minified = etree.tostring(root, pretty_print=False, encoding="utf-8")
                    cipher = aes_cbc_encrypt_raw(minified, key, iv)
                    out = base64.b64encode(cipher)
                    await bot.send_document(chat_id, types.InputFile(BytesIO(out), filename=Path(name).stem + ".enc.b64"))
                    await cb.message.reply("Файл зашифрован.")
                    done = True
                except Exception:
                    pass
            if not done:
                await cb.message.reply("Не удалось распознать JSON/XML — шифрование не выполнено.")
        except Exception as e:
            await cb.message.reply(f"Ошибка: {e}")
        finally:
            PENDING.pop(chat_id, None)
            await cb.message.reply("Возврат в главное меню.", reply_markup=main_menu_kb())
        return

@dp.message_handler(commands=["menu"])
async def cmd_menu(message: types.Message):
    await message.reply("Главное меню:", reply_markup=main_menu_kb())

async def do_decrypt(chat_id: int, name: str, data: bytes):
    lower = name.lower()
    if lower.endswith(".zip"):
        out_bytes = process_archive_recursive_and_build(data, action="decrypt")
        await bot.send_document(chat_id, types.InputFile(BytesIO(out_bytes), filename=name))
        return
    try:
        ext, outb, _ = process_encrypted_text_bytes(data)
        out_name = Path(name).stem + ext
        await bot.send_document(chat_id, types.InputFile(BytesIO(outb), filename=out_name))
        return
    except Exception:
        pass
    try:
        out_name, outb, _ = process_encrypted_archive_bytes(data)
        await bot.send_document(chat_id, types.InputFile(BytesIO(outb), filename=out_name))
        return
    except Exception:
        pass
    # try Unity
    try:
        out_name, outb = extract_unity_textassets_to_zip(data, name)
        await bot.send_document(chat_id, types.InputFile(BytesIO(outb), filename=out_name))
        return
    except Exception:
        pass
    await bot.send_message(chat_id, "Не удалось распознать или расшифровать файл.")

async def do_encrypt(chat_id: int, name: str, data: bytes):
    # ask key for single file
    if not TEXT_KEYS:
        await bot.send_message(chat_id, "Нет текстовых ключей (AES_TEXT_*) в окружении.")
        return
    PENDING[chat_id] = {"mode": "single_encrypt_choose", "bytes": data, "name": name}
    await bot.send_message(chat_id, "Выберите ключ для шифрования JSON/XML:", reply_markup=kb_choose_text_key())

async def do_archive_process(chat_id: int, name: str, data: bytes, action: str = "decrypt"):
    if action == "decrypt":
        out_bytes = process_archive_recursive_and_build(data, action="decrypt")
        await bot.send_document(chat_id, types.InputFile(BytesIO(out_bytes), filename=name))
    else:
        if not TEXT_KEYS:
            await bot.send_message(chat_id, "Нет текстовых ключей.")
            return
        PENDING[chat_id] = {"mode": "archive_encrypt_choose", "bytes": data, "name": name}
        await bot.send_message(chat_id, "Выберите текстовый ключ для шифрования архива:", reply_markup=kb_choose_text_key())

if __name__ == "__main__":
    executor.start_polling(dp, skip_updates=True)