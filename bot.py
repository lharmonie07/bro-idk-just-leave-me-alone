import os
import logging
import base64
import re
import json
from io import BytesIO
from zipfile import ZipFile
from lxml import etree
import aiohttp

from aiogram import Bot, Dispatcher, types
from aiogram.types import ContentType, InlineKeyboardMarkup, InlineKeyboardButton
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
        parser = etree.XMLParser(remove_blank_text=True)
        xml_obj = etree.fromstring(raw_bytes, parser)
        pretty = etree.tostring(xml_obj, pretty_print=True, encoding='utf-8')
        return filename + ".xml", pretty
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
        parser = etree.XMLParser(remove_blank_text=True)
        xml_obj = etree.fromstring(dec, parser)
        pretty = etree.tostring(xml_obj, pretty_print=True, encoding='utf-8')
        return filename + ".xml", pretty
    except Exception:
        pass

    return filename + ".txt", dec

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

@dp.message_handler(lambda message: re.search(r'https?://\S+', message.text or ""))
async def handle_link(message: types.Message):
    url = re.search(r'(https?://\S+)', message.text).group(1)
    try:
        async with aiohttp.ClientSession() as session:
            async with session.head(url) as resp:
                size = resp.headers.get('Content-Length', 'неизвестно')
                info_text = f"Файл: {os.path.basename(url)}\nРазмер: {size} байт"
    except Exception:
        info_text = f"Файл: {os.path.basename(url)}\nРазмер: неизвестно"

    keyboard = InlineKeyboardMarkup()
    keyboard.add(InlineKeyboardButton("Расшифровать", callback_data=f"decrypt|{url}"))
    keyboard.add(InlineKeyboardButton("Отмена", callback_data="cancel"))

    await message.reply(info_text, reply_markup=keyboard)

@dp.callback_query_handler(lambda c: c.data)
async def handle_buttons(callback_query: types.CallbackQuery):
    data = callback_query.data
    if data.startswith("decrypt|"):
        url = data.split("|")[1]
        await callback_query.answer("Обработка...")
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as resp:
                    data_bytes = await resp.read()
            if url.lower().endswith(".zip.enc") or url.lower().endswith(".zip"):
                out_name, out_bytes = process_encrypted_zip(data_bytes, os.path.basename(url))
            else:
                out_name, out_bytes = process_encrypted_text_file(data_bytes, os.path.basename(url))
            await bot.send_document(
                callback_query.message.chat.id,
                types.InputFile(BytesIO(out_bytes), filename=out_name)
            )
        except Exception as e:
            await bot.send_message(callback_query.message.chat.id, f"Ошибка при расшифровке: {e}")
    elif data == "cancel":
        await callback_query.answer("Отменено.")

if __name__ == "__main__":
    executor.start_polling(dp, skip_updates=True)