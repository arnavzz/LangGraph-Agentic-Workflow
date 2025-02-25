import os 
from dotenv import load_dotenv

load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
TARGET_SCOPE = os.getenv("TARGET_SCOPE")

if not GROQ_API_KEY:
    raise ValueError ("GROQ_API_KEY is missing! Please add it to your .env file.")

print(f"Target Scope: {TARGET_SCOPE}")