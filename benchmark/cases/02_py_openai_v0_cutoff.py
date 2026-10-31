import openai

def summarize_diff(diff_text: str) -> str:
    resp = openai.ChatCompletion.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": diff_text}],
    )
    return resp["choices"][0]["message"]["content"]
