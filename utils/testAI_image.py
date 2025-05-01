from openai import OpenAI
client = OpenAI()

try:
    client.chat.completions.create(
        model="gpt-4.1-mini",
        messages=[{
            "role": "user",
            "content": [
                {"type": "text", "text": "Hello, what's in this image?"},
                {"type": "image_url", "image_url": {"url": "https://upload.wikimedia.org/wikipedia/commons/4/47/PNG_transparency_demonstration_1.png"}}
            ]
        }],
        max_tokens=10
    )
    print("✅ You have access to GPT-4 Vision.")
except Exception as e:
    print("❌ Vision model not available:", e)
