from dotenv import load_dotenv
import os

load_dotenv()
TOKEN = os.getenv("TELEGRAM_TOKEN")

print(f"Token loaded: {TOKEN}")
print(f"Token exists: {TOKEN is not None}")
