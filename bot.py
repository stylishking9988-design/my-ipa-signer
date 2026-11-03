
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

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🍎 Welcome to My IPA Signer!\n\n"
        "📦 Send IPA to begin\n"
        "🔐 /certs - Certificate status\n"
        "ℹ️ /help - Help"
    )

async def help_command(update: Update, context):
    await update.message.reply_text(
        "/start - Main menu\n"
        "/certs - Certificate status\n"
        "/help - Help"
    )

async def certs(update: Update, context):
    await update.message.reply_text(
        "🔐 No signing certificate configured yet."
    )

async def receive_ipa(update: Update, context):
    doc = update.message.document

    if not (doc.file_name or "").lower().endswith(".ipa"):
        await update.message.reply_text("Please send a valid IPA file.")
        return

    await update.message.reply_text(
        "✅ IPA received! Signing engine setup is pending."
    )

app = Application.builder().token(
    os.environ["BOT_TOKEN"]
).build()

app.add_handler(CommandHandler("start", start))
app.add_handler(CommandHandler("help", help_command))
app.add_handler(CommandHandler("certs", certs))
app.add_handler(
    MessageHandler(filters.Document.ALL, receive_ipa)
)

app.run_webhook(
    listen="0.0.0.0",
    port=int(os.environ.get("PORT", "10000")),
    url_path="telegram",
    webhook_url=(
        f"https://{os.environ['RENDER_EXTERNAL_HOSTNAME']}"
        "/telegram"
    ),
    secret_token=os.environ["WEBHOOK_SECRET"],
)
