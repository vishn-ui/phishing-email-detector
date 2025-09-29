# ai_analyzer.py
import os
import sys
import json
import google.generativeai as genai

def analyze_email_with_ai(email_content: str) -> dict:
    """
    Analyzes raw email content using the Google Gemini API for phishing detection.
    """
    # 1. --- Configure the API Key ---
    try:
        api_key = os.environ["GOOGLE_API_KEY"]
        genai.configure(api_key=api_key)
    except KeyError:
        return {"error": "API Key not found. Please set the GOOGLE_API_KEY environment variable."}

    # 2. --- Define the System Prompt and JSON Schema ---
    # This is our instruction set for the AI model.
    system_instruction = """
    You are a world-class cybersecurity analyst specializing in phishing detection. 
    Your task is to analyze the provided raw email text and identify any characteristics 
    of a phishing attempt. Be highly critical; it's better to be overly cautious.
    
    Analyze the following aspects:
    1.  Sender Information: Mismatched "From" vs. "Reply-To" domains, suspicious sender domains.
    2.  Suspicious Links: URL shorteners, domain impersonation (homographs), link text vs. actual href mismatch.
    3.  Urgent or Threatening Language: Keywords that create fear or a sense of urgency.
    4.  Spelling and Grammar: Unprofessional errors that are uncharacteristic of a legitimate company.
    5.  Generic Greetings: Greetings like "Dear Customer" instead of a personal name.
    6.  Unexpected Attachments: The presence of unexpected or suspiciously named attachments.

    Based on your complete analysis, provide a structured JSON response. The risk level should
    be HIGH if multiple strong indicators are present, MEDIUM if there are some suspicious
    elements, and LOW if it appears legitimate.
    """

    # This defines the exact structure of the JSON output we want from the model.
    response_schema = {
        "risk_level": "LOW | MEDIUM | HIGH",
        "summary": "A brief, one-sentence summary of your findings.",
        "indicators": [
            {
                "type": "e.g., Suspicious Link, Urgent Language, Sender Anomaly",
                "details": "A specific explanation of what was found and why it is suspicious.",
                "evidence": "The exact text snippet from the email that triggered this indicator.",
            }
        ]
    }
    
    # 3. --- Initialize and Call the Model ---
    # We use gemini-1.5-flash for its speed and capability.
    model = genai.GenerativeModel(
        model_name="gemini-1.5-flash",
        system_instruction=system_instruction,
        generation_config=genai.GenerationConfig(
            response_mime_type="application/json",
            response_schema=response_schema
        )
    )
    
    try:
        response = model.generate_content(email_content)
        # The response text should be a valid JSON string based on our schema.
        return json.loads(response.text)
    except Exception as e:
        return {"error": f"Failed to get a valid analysis from the AI model. Details: {e}"}

# --- Main block to run the script interactively ---
if __name__ == "__main__":
    print("--- AI-Powered Phishing Analyzer ---")
    print("Paste your email content below. Press Ctrl+D (Mac/Linux) or Ctrl+Z then Enter (Windows) when you're done.")
    print("-" * 40)

    email_text = sys.stdin.read()

    if not email_text.strip():
        print("\nNo input received. Exiting.")
    else:
        print("\n--- Contacting Google AI for Analysis... ---")
        report = analyze_email_with_ai(email_text)
        
        print("\n--- AI Analysis Report ---")
        print(json.dumps(report, indent=2))