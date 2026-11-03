
import os
import logging
import asyncio

from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)

TOKEN = os.environ["BOT_TOKEN"]
SECRET = os.environ["WEBHOOK_SECRET"]
HOST = os.environ["RENDER_EXTERNAL_HOSTNAME"]
PORT = int(os.environ.get("PORT", "10000"))


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🍎 Welcome to My IPA Signer!\n\n"
        "📦 Send IPA - Upload your IPA\n"
        "🔐 /certs - Certificate status\n"
        "ℹ️ /help - Help menu"
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🍎 My IPA Signer\n\n"
        "/start - Main menu\n"
        "/certs - Certificate status\n"
        "/help - Help"
    )


async def certs(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🔐 No signing certificate configured yet."
    )


async def receive_ipa(update: Update, context: ContextTypes.DEFAULT_TYPE):
    doc = update.message.document

    if not (doc.file_name or "").lower().endswith(".ipa"):
        await update.message.reply_text("Please send a valid IPA file.")
        return

    await update.message.reply_text(
        "✅ IPA received!\n"
        "Signing engine is not configured yet."
    )


async def main():
    app = Application.builder().token(TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("certs", certs))

    app.add_handler(
        MessageHandler(filters.Document.ALL, receive_ipa)
    )

    await app.initialize()
    await app.start()

    await app.updater.start_webhook(
        listen="0.0.0.0",
        port=PORT,
        url_path="telegram",
        webhook_url=f"https://{HOST}/telegram",
        secret_token=SECRET,
    )

    logging.info("My IPA Signer started successfully!")

    try:
        await asyncio.Event().wait()
    finally:
        await app.updater.stop()
        await app.stop()
        await app.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
