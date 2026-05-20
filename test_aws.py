import os
import json
from dotenv import load_dotenv
from mcp_sentinel_server import create_aws_snapshot, delete_aws_snapshot

load_dotenv(override=True)

TARGET_HOST = os.getenv("TARGET_HOST")
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.getenv("AWS_DEFAULT_REGION", "eu-north-1")

def test():
    print(f"Diagnostics: KeyID={AWS_ACCESS_KEY[:8]}..., Region={AWS_REGION}")
    print(f"--- Creating AWS Snapshot for {TARGET_HOST} ---")
    res_str = create_aws_snapshot(
        host=TARGET_HOST,
        aws_access_key=AWS_ACCESS_KEY,
        aws_secret_key=AWS_SECRET_KEY,
        region=AWS_REGION
    )
    res = json.loads(res_str)
    
    if "error" in res:
        print(f"Error: {res['error']}")
        return None
    
    print(f"Success! Snapshot IDs: {res['snapshots']}")
    return res['snapshots']

if __name__ == "__main__":
    snaps = test()
    if snaps:
        # We output the snapshots in a predictable way for the agent to parse
        print(f"RESULT_SNAPSHOTS={json.dumps(snaps)}")
