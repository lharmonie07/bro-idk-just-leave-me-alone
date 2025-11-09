import os
import logging
import base64
import re
import json
from io import BytesIO
from zipfile import ZipFile
from xml.dom import minidom
import aiohttp

from aiogram import Bot, Dispatcher, types
from aiogram.types import ContentType
from aiogram.utils import executor
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def load_keys(prefix: str):
    keys = []
    idx = 1
    while True:
        key_var = f"{prefix}_KEY_HEX" if idx == 1 else f"{prefix}_KEY_HEX_{idx}"
        iv_var = f"{prefix}_IV_HEX" if idx == 1 else f"{prefix}_IV_HEX_{idx}"
        key_hex = os.getenv(key_var)
        iv_hex = os.getenv(iv_var)
        if not key_hex or not iv_hex:
            break
        keys.append((bytes.fromhex(key_hex), bytes.fromhex(iv_hex)))
        idx += 1
    return keys

BOT_TOKEN = os.getenv("BOT_TOKEN")
TEXT_KEYS = load_keys("AES_TEXT")
ARCHIVE_KEYS = load_keys("AES_ARCHIVE")

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher(bot)

def aes_cbc_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(data)
    return unpad(decrypted, AES.block_size)

def try_decrypt_with_keys(data: bytes, keys):
    for key, iv in keys:
        try:
            return aes_cbc_decrypt(data, key, iv)
        except Exception:
            continue
    raise RuntimeError("Не удалось расшифровать файл ни одним ключом.")

def process_encrypted_zip(zip_bytes: bytes, orig_name: str):
    with ZipFile(BytesIO(zip_bytes)) as z:
        candidate = None
        for name in z.namelist():
            low = name.lower()
            if low.endswith((".sig", ".rsa", ".pem", ".zip.sha")) or name.endswith("/"):
                continue
            candidate = name
            break
        if not candidate:
            raise RuntimeError("Не найден зашифрованный файл внутри архива.")
        enc_bytes = z.read(candidate)
        dec = try_decrypt_with_keys(enc_bytes, ARCHIVE_KEYS)
        out_name = os.path.basename(candidate)
        if out_name.endswith(".enc"):
            out_name = out_name[:-4]
        return out_name, dec

def process_encrypted_text_file(raw_bytes: bytes, orig_name: str):
    filename = os.path.splitext(os.path.basename(orig_name))[0]
    try:
        obj = json.loads(raw_bytes.decode("utf-8"))
        pretty = json.dumps(obj, ensure_ascii=False, indent=2)
        return filename + ".json", pretty.encode("utf-8")
    except Exception:
        pass
    try:
        dom = minidom.parseString(raw_bytes.decode("utf-8"))
        pretty = dom.toprettyxml(indent="  ")
        return filename + ".xml", pretty.encode("utf-8")
    except Exception:
        pass
    text = raw_bytes.decode("utf-8", errors="ignore").strip()
    try:
        b64_decoded = base64.b64decode(text)
    except Exception as e:
        raise ValueError("Файл не в формате base64 или повреждён.") from e
    dec = try_decrypt_with_keys(b64_decoded, TEXT_KEYS)
    try:
        data_obj = json.loads(dec.decode("utf-8"))
        pretty = json.dumps(data_obj, ensure_ascii=False, indent=2)
        return filename + ".json", pretty.encode("utf-8")
    except Exception:
        pass
    try:
        dom = minidom.parseString(dec)
        pretty = dom.toprettyxml(indent="  ")
        return filename + ".xml", pretty.encode("utf-8")
    except Exception:
        pass
    try:
        return filename + ".txt", dec
    except Exception:
        return filename + ".bin", dec

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
        "*Незначительные исправления.\n"
    )
    await message.reply(changes)

@dp.message_handler(content_types=ContentType.DOCUMENT)
async def handle_document(message: types.Message):
    doc = message.document
    filename = doc.file_name or "file"
    file_obj = await bot.get_file(doc.file_id)
    file_bytes = await bot.download_file(file_obj.file_path)
    data = file_bytes.read()
    try:
        if filename.lower().endswith(".zip"):
            out_name, out_bytes = process_encrypted_zip(data, filename)
        else:
            out_name, out_bytes = process_encrypted_text_file(data, filename)
        await bot.send_document(
            message.chat.id,
            types.InputFile(BytesIO(out_bytes), filename=out_name),
            reply_to_message_id=message.message_id
        )
    except Exception as e:
        await message.reply(f"Ошибка при расшифровке: {e}", reply_to_message_id=message.message_id)

@dp.message_handler(lambda message: re.search(r'https?://\S+', message.text or ""))
async def handle_link(message: types.Message):
    url = re.search(r'(https?://\S+)', message.text).group(1)
    await message.reply("Обработка...")
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"Ошибка загрузки: {resp.status}")
                data = await resp.read()
        if url.lower().endswith(".zip.enc") or url.lower().endswith(".zip"):
            out_name, out_bytes = process_encrypted_zip(data, os.path.basename(url))
        else:
            out_name, out_bytes = process_encrypted_text_file(data, os.path.basename(url))
        await bot.send_document(
            message.chat.id,
            types.InputFile(BytesIO(out_bytes), filename=out_name),
            reply_to_message_id=message.message_id
        )
    except Exception as e:
        await message.reply(f"Ошибка при обработке ссылки: {e}", reply_to_message_id=message.message_id)

if __name__ == "__main__":
    executor.start_polling(dp, skip_updates=True)