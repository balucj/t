import asyncio
import os
from dotenv import load_dotenv
from advisor import consult_advisor

load_dotenv()

async def test_advisor():
    print("--- Testing Cloud Advisor ---")
    prompt = "How do I check the version of Amazon SSM Agent on Windows using PowerShell?"
    print(f"Prompt: {prompt}")
    
    result = consult_advisor(prompt)
    print("\n--- Response from Advisor ---")
    print(result)

if __name__ == "__main__":
    if not os.getenv("OPENAI_API_KEY"):
        print("Error: OPENAI_API_KEY not found in .env")
    else:
        asyncio.run(test_advisor())
