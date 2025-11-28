import requests
import json
import sys

def submit(filename, language="cpp"):
    url = "http://154.57.164.67:31255/run"
    
    try:
        with open(filename, 'r') as f:
            code = f.read()
    except FileNotFoundError:
        print(f"Error: File {filename} not found.")
        return

    payload = {
        "code": code,
        "language": language
    }
    
    headers = {
        "Content-Type": "application/json"
    }
    
    print(f"Submitting {filename} as {language}...")
    try:
        response = requests.post(url, json=payload, headers=headers)
        print(f"Status Code: {response.status_code}")
        try:
            data = response.json()
            print("Response JSON:")
            print(json.dumps(data, indent=2))
            
            if data.get("challengeCompleted"):
                print("\nSUCCESS! Flag found!")
                print(data.get("flag"))
            elif data.get("result"):
                res = data.get("result")
                print(f"\nTest Result: {res.get('cause', 'Unknown')}")
                if res.get("error"):
                    print(f"Error: {res.get('error')}")
                if res.get("runtime_error"):
                    print(f"Runtime Error: {res.get('runtime_error')}")
                    
        except json.JSONDecodeError:
            print("Response is not JSON:")
            print(response.text)
            
    except requests.RequestException as e:
        print(f"Request failed: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 submit.py <filename> [language]")
    else:
        fname = sys.argv[1]
        lang = sys.argv[2] if len(sys.argv) > 2 else "cpp"
        submit(fname, lang)
