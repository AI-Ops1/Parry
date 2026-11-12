from openai import OpenAI

client = OpenAI()

def ask(prompt: str) -> str:
    res = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}]
    )
    return res.choices[0].message.content or ""
