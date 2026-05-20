# from azure.core.pipeline.transport import HttpRequest
from requests import request
from fsspec import json
import asyncio
import re
import os
import json 
import litellm
from loguru import logger

class CloudAdvisor:
    """
    The Cloud-based Intelligence Agent (ChatGPT). 
    Handles non-sensitive logic and technical recommendations.
    """
    
    def __init__(self, api_key: str = None, model: str = "openai/gpt-4o"):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.model = model

    def _anonymize(self, text: str) -> str:
        """Strip sensitive identifiers (IPs, emails) from text before sending to cloud."""
        # Strip IPv4
        text = re.sub(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', '[REDACTED_IP]', text)
        # Strip SSH Hostnames/Usernames/Emails
        text = re.sub(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', '[REDACTED_EMAIL]', text)
        return text

    def get_intelligence(self, prompt: str) -> str:
        """Query ChatGPT with an anonymized prompt and forced output format."""
        if not self.api_key:
            return "Expert Advisor Unavailable: No OPENAI_API_KEY found in environment."
            
        # Force a structured response format to ensure the Local Sentinel can parse it
        structured_prompt = (
            f"{prompt}\n\n"
            """Return ONLY a valid JSON object in the following format (no extra text, no code block):
                {
                "SEVERITY": (integer from 0-100 based on impact),
                "WARNINGS": [
                    "warning 1",
                    "warning 2",
                    "warning 3"
                ],
                "RESTART_REQUIRED": (boolean: true if a reboot or service restart is recommended),
                "PROCEDURE": [
                    "exact command 1",
                    "exact command 2"
                ],
                "VALIDATION": "single command to confirm the new version is active"}
                
                CRITICAL CONSTRAINTS:

                Detect OS.
                Use the Exact Package ID (e.g., Microsoft.VCRedist.2015+.x64 instead of Microsoft Visual C++).
                If OS is Windows:
                    Use winget ONLY.
                    DO NOT use msstore source.
                    MUST use the exact winget package ID (no display names, no quotes).
                    Prefer install --id <exact_id> --version <version> instead of upgrade to avoid detection issues.
                    Ensure commands do not trigger msstore fallback.
                    Provide at least one valid install/upgrade command.]
                    You MUST include --source winget to bypass msstore certificate errors.
                    You MUST include --accept-package-agreements --accept-source-agreements.
                    Use upgrade --id instead of install.
                If OS is Linux:
                    Use default package manager (apt or yum) without modification.
                Ensure commands are executable and avoid known issues and certificate/source errors.
                Keep output strictly in required JSON format.
            """
        )
        
        clean_prompt = self._anonymize(structured_prompt)
        logger.info(f"Consulting Cloud Advisor (Anonymized)...")
        logger.info(f"Clean Prompt: {clean_prompt}")
        
        try:
            response = litellm.completion(
                model=self.model,
                messages=[{"role": "user", "content": clean_prompt}],
                api_key=self.api_key,
                temperature=0.3)
            
            raw_content = response.choices[0].message.content
            if not raw_content:
                 logger.error("Cloud Advisor returned an empty response.")
                 return {}
                 
            # Strip JSON code blocks if they exist
            if raw_content.startswith("```json"):
                 raw_content = raw_content.replace("```json", "", 1).replace("```", "", 1).strip()
            elif raw_content.startswith("```"):
                 raw_content = raw_content.replace("```", "", 2).strip()

            result = json.loads(raw_content)
            logger.success(result)
            
            # Ensure PROCEDURE is a list before finalizing
            if "PROCEDURE" in result:
                if isinstance(result["PROCEDURE"], str):
                    result["PROCEDURE"] = [result["PROCEDURE"]]
                if isinstance(result["PROCEDURE"], list):
                    result["PROCEDURE"] = finalize_commands(result["PROCEDURE"])
                else:
                    result["PROCEDURE"] = []
            else:
                result["PROCEDURE"] = []

            return result
        except Exception as e:
            logger.error(f"Cloud Advisor Error: {e}")
            if 'raw_content' in locals():
                logger.debug(f"Raw Response: {raw_content}")
            return {}
# Your input list


def finalize_commands(command_list):
    sanitized = []
    for cmd in command_list:

        if cmd.startswith("winget"):
            # 1. Check/Add Source Lock
            if "--source winget" not in cmd:
                cmd = f"{cmd.strip()} --source winget"

            # 2. Check/Add Agreements
        # We check for the first flag to see if the block is missing
            if "--accept-package-agreements" not in cmd:
                cmd = f"{cmd.strip()} --accept-package-agreements --accept-source-agreements"

        # 3. Handle quoting for package IDs with spaces (after --id)
        # Find --id parameter and quote its value if it contains spaces and isn't already quoted
        # We stop at the next flag (starting with --)
        import re
        def quote_id_value(match):
            prefix = match.group(1)  # --id
            value = match.group(2).rstrip()   # the value after --id, strip trailing spaces only
            
            # If value contains spaces and isn't already quoted, quote it
            if ' ' in value and not (value.startswith('"') and value.endswith('"')):
                return f'{prefix} "{value}" '
            return f'{prefix} {value} '

        # Match --id followed by characters that are NOT the start of another flag
        cmd = re.sub(r'(--id)\s+((?:(?!--).)+)', quote_id_value, cmd)

        # 4. Clean up any accidental double-spacing
        cmd = " ".join(cmd.split())

        sanitized.append(cmd)
    return sanitized

# Execute

# Standalone helper function for easy access
def consult_advisor(prompt: str) -> str:
    """Helper function to quickly query the Cloud Advisor."""
    advisor = CloudAdvisor()
    return advisor.get_intelligence(prompt)
