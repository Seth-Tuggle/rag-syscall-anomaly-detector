import os
from openai import OpenAI
from dotenv import load_dotenv

# Load .env file if it exists. Make sure your file ends with .env
load_dotenv(dotenv_path=r"C:\Radford_University\RU_fall_2025\CS645\ragAI\openai.env") 

api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    print("No API key found. Set OPENAI_API_KEY in environment or .env file. This error usually occurs if you saved your openai.env file as openai.env.txt.")
    exit(1)

client = OpenAI(api_key=api_key)

try:
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": "Hello! What is 400 + 45?"}]
    )
    print("Response from OpenAI:")
    print(response.choices[0].message.content)
except Exception as e:
    print("Connection failed or invalid API key.")
    print("Error:", e)