
import os
import re
import sqlite3
import logging
import tempfile
from pathlib import Path
from io import BytesIO

from cryptography.fernet import Fernet
from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)

# ---------------- CONFIG ----------------

BOT_TOKEN = os.environ["BOT_TOKEN"]
WEBHOOK_SECRET = os.environ["WEBHOOK_SECRET"]
FERNET_KEY = os.environ["FERNET_KEY"].encode()

ADMIN_IDS = {
    int(x.strip())
    for x in os.environ["ADMIN_IDS"].split(",")
    if x.strip().isdigit()
}

DATA_DIR = Path(os.getenv("DATA_DIR", "/var/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA_DIR / "bot_users.sqlite3"
WEBHOOK_PATH = "my-ipa-signer-hook"
MAX_CERT_SIZE = 10 * 1024 * 1024

cipher = Fernet(FERNET_KEY)

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logging.getLogger("httpx").setLevel(logging.WARNING)


# ---------------- DATABASE ----------------

def db():
    conn = sqlite3.connect(DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY,
                username TEXT,
                first_name TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)


def register_user(user):
    with db() as conn:
        conn.execute("""
            INSERT INTO users (user_id, username, first_name)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                username=excluded.username,
                first_name=excluded.first_name
        """, (user.id, user.username, user.first_name))


def get_user(user_id):
    with db() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE user_id=?",
            (user_id,)
        ).fetchone()


def set_status(user_id, status):
    with db() as conn:
        conn.execute("""
            UPDATE users SET status=? WHERE user_id=?
        """, (status, user_id))


def all_users(status=None):
    with db() as conn:
        if status:
            return conn.execute(
                "SELECT * FROM users WHERE status=? ORDER BY created_at DESC",
                (status,)
            ).fetchall()
        return conn.execute(
            "SELECT * FROM users ORDER BY created_at DESC"
        ).fetchall()


# ---------------- SECURITY / FILES ----------------

def is_admin(user_id):
    return user_id in ADMIN_IDS


def user_folder(user_id):
    # Telegram user IDs are integers, not user-provided paths.
    folder = DATA_DIR / str(int(user_id))
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        folder.chmod(0o700)
    except OSError:
        pass
    return folder


def save_encrypted(user_id, filename, data):
    folder = user_folder(user_id)
    encrypted = cipher.encrypt(data)

    fd, temp_name = tempfile.mkstemp(dir=str(folder))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(encrypted)
        os.chmod(temp_name, 0o600)
        os.replace(temp_name, folder / filename)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def certificate_status(user_id):
    folder = DATA_DIR / str(int(user_id))
    return (
        (folder / "certificate.p12.enc").is_file(),
        (folder / "profile.mobileprovision.enc").is_file(),
    )


def delete_cert_files(user_id):
    folder = DATA_DIR / str(int(user_id))
    deleted = False

    for name in ("certificate.p12.enc", "profile.mobileprovision.enc"):
        path = folder / name
        if path.exists():
            path.unlink()
            deleted = True

    return deleted


def user_allowed(user_id):
    if is_admin(user_id):
        return True
    row = get_user(user_id)
    return bool(row and row["status"] == "approved")


# ---------------- USER COMMANDS ----------------

async def myid(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        f"Your Telegram numeric ID: {update.effective_user.id}"
    )


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    register_user(user)

    if is_admin(user.id):
        await update.message.reply_text(
            "Welcome, Admin!\nUse /admin to open your dashboard."
        )
        return

    row = get_user(user.id)

    if row["status"] == "approved":
        await update.message.reply_text(
            "Welcome to My IPA Signer!\n\n"
            "Commands:\n"
            "/savep12 - Save your P12 certificate\n"
            "/savemp - Save your MobileProvision profile\n"
            "/status - Check your saved files\n"
            "/deletecert - Delete your saved files\n"
            "/help - Help"
        )
    elif row["status"] == "blocked":
        await update.message.reply_text(
            "Your access is blocked. Please contact the bot admin."
        )
    else:
        await update.message.reply_text(
            "Your access request has been registered.\n"
            "Please wait for admin approval."
        )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not user_allowed(update.effective_user.id):
        await update.message.reply_text("Your account is not approved yet.")
        return

    await update.message.reply_text(
        "Use /savep12 to upload your .p12 file.\n"
        "Use /savemp to upload your .mobileprovision file.\n"
        "Use /status to check your saved files.\n"
        "Use /deletecert to delete your files.\n\n"
        "IPA signing is not enabled in this version."
    )


async def savep12(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not user_allowed(update.effective_user.id):
        await update.message.reply_text("Access not approved.")
        return

    context.user_data["waiting_for"] = "p12"
    await update.message.reply_text(
        "Upload your own .p12 certificate as a document."
    )


async def savemp(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not user_allowed(update.effective_user.id):
        await update.message.reply_text("Access not approved.")
        return

    context.user_data["waiting_for"] = "mobileprovision"
    await update.message.reply_text(
        "Upload your own .mobileprovision file as a document."
    )


async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    doc = update.message.document

    if not user_allowed(user.id):
        await update.message.reply_text("Access not approved.")
        return

    waiting = context.user_data.get("waiting_for")
    if not waiting:
        await update.message.reply_text(
            "First use /savep12 or /savemp."
        )
        return

    filename = (doc.file_name or "").lower()

    if waiting == "p12":
        if not filename.endswith(".p12"):
            await update.message.reply_text("Please upload a .p12 file.")
            return
        target = "certificate.p12.enc"
    else:
        if not filename.endswith(".mobileprovision"):
            await update.message.reply_text(
                "Please upload a .mobileprovision file."
            )
            return
        target = "profile.mobileprovision.enc"

    if doc.file_size and doc.file_size > MAX_CERT_SIZE:
        await update.message.reply_text("Maximum file size is 10 MB.")
        return

    try:
        tg_file = await doc.get_file()
        buffer = BytesIO()
        await tg_file.download_to_memory(out=buffer)
        data = buffer.getvalue()

        if not data or len(data) > MAX_CERT_SIZE:
            await update.message.reply_text("Invalid or oversized file.")
            return

        save_encrypted(user.id, target, data)
        context.user_data.pop("waiting_for", None)

        await update.message.reply_text(
            "Your certificate file was saved encrypted.\n"
            "Use /status to check your files."
        )
    except Exception:
        logging.exception("Certificate upload failed for user %s", user.id)
        await update.message.reply_text(
            "Could not save the file. Please try again."
        )


async def status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id

    if not user_allowed(user_id):
        await update.message.reply_text("Access not approved.")
        return

    p12, profile = certificate_status(user_id)
    await update.message.reply_text(
        "Your certificate status:\n"
        f"P12: {'Saved' if p12 else 'Not saved'}\n"
        f"MobileProvision: {'Saved' if profile else 'Not saved'}"
    )


async def deletecert(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id

    if not user_allowed(user_id):
        await update.message.reply_text("Access not approved.")
        return

    deleted = delete_cert_files(user_id)
    context.user_data.pop("waiting_for", None)

    await update.message.reply_text(
        "Your saved certificate files were deleted."
        if deleted else "No saved certificate files found."
    )


# ---------------- ADMIN COMMANDS ----------------

async def admin(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        await update.message.reply_text("Admin only command.")
        return

    users = all_users()
    pending = sum(1 for u in users if u["status"] == "pending")
    approved = sum(1 for u in users if u["status"] == "approved")
    blocked = sum(1 for u in users if u["status"] == "blocked")

    await update.message.reply_text(
        "MY IPA SIGNER - ADMIN DASHBOARD\n\n"
        f"Total users: {len(users)}\n"
        f"Pending: {pending}\n"
        f"Approved: {approved}\n"
        f"Blocked: {blocked}\n\n"
        "Commands:\n"
        "/users\n"
        "/user USER_ID\n"
        "/approve USER_ID\n"
        "/block USER_ID\n"
        "/unblock USER_ID\n"
        "/certstatus\n"
        "/deleteuser USER_ID\n"
        "/broadcast (reply to a message)"
    )


async def users_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        return

    users = all_users()
    if not users:
        await update.message.reply_text("No registered users.")
        return

    lines = ["Registered users:"]
    for u in users[:50]:
        username = f"@{u['username']}" if u["username"] else "No username"
        lines.append(
            f"{u['user_id']} | {username} | {u['status']}"
        )

    if len(users) > 50:
        lines.append(f"...and {len(users) - 50} more.")

    await update.message.reply_text("\n".join(lines))


async def user_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        return

    if not context.args or not context.args[0].isdigit():
        await update.message.reply_text("Usage: /user USER_ID")
        return

    uid = int(context.args[0])
    row = get_user(uid)

    if not row:
        await update.message.reply_text("User not found.")
        return

    p12, profile = certificate_status(uid)
    await update.message.reply_text(
        f"User ID: {uid}\n"
        f"Username: @{row['username'] or 'None'}\n"
        f"Name: {row['first_name'] or 'Unknown'}\n"
        f"Access: {row['status']}\n"
        f"P12 saved: {'Yes' if p12 else 'No'}\n"
        f"MobileProvision saved: {'Yes' if profile else 'No'}"
    )


async def approve(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        return

    if not context.args or not context.args[0].isdigit():
        await update.message.reply_text("Usage: /approve USER_ID")
        return

    uid = int(context.args[0])
    if not get_user(uid):
        await update.message.reply_text("User not found. Ask them to send /start.")
        return

    set_status(uid, "approved")
    await update.message.reply_text(f"User {uid} approved.")

    try:
        await context.bot.send_message(
            uid, "Your My IPA Signer access has been approved. Send /start."
        )
    except Exception:
        pass


async def block(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        return

    if not context.args or not context.args[0].isdigit():
        await update.message.reply_text("Usage: /block USER_ID")
        return

    uid = int(context.args[0])
    if not get_user(uid):
        await update.message.reply_text("User not found.")
        return

    if is_admin(uid):
        await update.message.reply_text("You cannot block an admin.")
        return

    set_status(uid, "blocked")
    await update.message.reply_text(f"User {uid} blocked.")


async def unblock(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        return

    if not context.args or not context.args[0].isdigit():
        await update.message.reply_text("Usage: /unblock USER_ID")
        return

    uid = int(context.args[0])
    if not get_user(uid):
        await update.message.reply_text("User not found.")
        return

    set_status(uid, "approved")
    await update.message.reply_text(f"User {uid} unblocked.")


async def certstatus(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        return

    users = all_users()
    p12_count = 0
    profile_count = 0

    for u in users:
        p12, profile = certificate_status(u["user_id"])
        p12_count += int(p12)
        profile_count += int(profile)

    await update.message.reply_text(
        f"Users: {len(users)}\n"
        f"Saved P12 files: {p12_count}\n"
        f"Saved MobileProvision files: {profile_count}"
    )


async def deleteuser(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        return

    if not context.args or not context.args[0].isdigit():
        await update.message.reply_text("Usage: /deleteuser USER_ID")
        return

    uid = int(context.args[0])
    if is_admin(uid):
        await update.message.reply_text("You cannot delete an admin's certificates.")
        return

    deleted = delete_cert_files(uid)
    if get_user(uid):
        set_status(uid, "blocked")

    await update.message.reply_text(
        f"User {uid}: certificate files deleted and access blocked."
        if deleted else
        f"User {uid}: no certificate files found; access blocked if registered."
    )


async def broadcast(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        return

    source = update.message.reply_to_message
    if not source:
        await update.message.reply_text(
            "Reply to the message you want to send, then type /broadcast."
        )
        return

    targets = all_users("approved")
    sent = 0
    failed = 0

    status_message = await update.message.reply_text(
        f"Broadcast started for {len(targets)} approved users."
    )

    for user in targets:
        try:
            await context.bot.copy_message(
                chat_id=user["user_id"],
                from_chat_id=update.effective_chat.id,
                message_id=source.message_id,
            )
            sent += 1
        except Exception:
            failed += 1

    await status_message.edit_text(
        f"Broadcast complete.\nSent: {sent}\nFailed: {failed}"
    )


# ---------------- ERROR HANDLER ----------------

async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE):
    logging.error("Bot error: %s", context.error)


# ---------------- START BOT ----------------

def main():
    if not ADMIN_IDS:
        raise RuntimeError("Set ADMIN_IDS in Render Environment Variables.")

    init_db()

    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("myid", myid))
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))

    app.add_handler(CommandHandler("savep12", savep12))
    app.add_handler(CommandHandler("savemp", savemp))
    app.add_handler(CommandHandler("status", status))
    app.add_handler(CommandHandler("deletecert", deletecert))

    app.add_handler(CommandHandler("admin", admin))
    app.add_handler(CommandHandler("users", users_command))
    app.add_handler(CommandHandler("user", user_command))
    app.add_handler(CommandHandler("approve", approve))
    app.add_handler(CommandHandler("block", block))
    app.add_handler(CommandHandler("unblock", unblock))
    app.add_handler(CommandHandler("certstatus", certstatus))
    app.add_handler(CommandHandler("deleteuser", deleteuser))
    app.add_handler(CommandHandler("broadcast", broadcast))

    app.add_handler(
        MessageHandler(filters.Document.ALL, handle_document)
    )
    app.add_error_handler(error_handler)

    hostname = os.environ["RENDER_EXTERNAL_HOSTNAME"]
    port = int(os.environ.get("PORT", "10000"))

    app.run_webhook(
        listen="0.0.0.0",
        port=port,
        url_path=WEBHOOK_PATH,
        webhook_url=f"https://{hostname}/{WEBHOOK_PATH}",
        secret_token=WEBHOOK_SECRET,
        allowed_updates=["message"],
    )


if __name__ == "__main__":
    main()
