import os
import logging
from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)

logging.basicConfig(level=logging.INFO)

TOKEN = os.environ["BOT_TOKEN"]
ADMIN_ID = int(os.environ.get("ADMIN_ID", "0"))
SECRET = os.environ["WEBHOOK_SECRET"]
HOST = os.environ["RENDER_EXTERNAL_HOSTNAME"]


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🍎 Welcome to My IPA Signer!\n\n"
        "📦 Send IPA: Upload an IPA file\n"
        "🔐 /certs - Certificate status\n"
        "ℹ️ /help - Help menu"
    )


async def help_command(update: Update, context):
    await update.message.reply_text(
        "My IPA Signer\n\n"
        "/start - Main menu\n"
        "/certs - Certificate status\n"
        "/help - Help"
    )


async def certs(update: Update, context):
    await update.message.reply_text(
        "🔐 No signing certificate configured yet."
    )


async def receive_ipa(update: Update, context):
    document = update.message.document

    if not document.file_name.lower().endswith(".ipa"):
        await update.message.reply_text("Please send a valid .ipa file.")
        return

    await update.message.reply_text(
        "✅ IPA received!\n"
        "⚠️ Signing is not configured yet. "
        "Please add your certificate setup first."
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
        port=int(os.environ.get("PORT", "10000")),
        url_path="telegram",
        webhook_url=f"https://{HOST}/telegram",
        secret_token=SECRET,
    )

    await app.updater.idle()


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
