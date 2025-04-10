import os
import logging
from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv
import google.generativeai as genai
from llm_guard.input_scanners import PromptInjection, Toxicity, Anonymize  # Example scanners
from llm_guard.output_scanners import NoRefusal # Example output scanner
from llm_guard import scan_prompt, scan_output

# --- Configuration ---
load_dotenv()  # Load environment variables from .env file

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize Flask app
app = Flask(__name__)

# --- LLM Guard Setup ---
# Define the input scanners 
# PromptInjection is key for the core requirement.
# Toxicity is often relevant. Anonymize can prevent data leaks.
input_scanners = [
    PromptInjection(threshold=0.75), # Adjust threshold as needed
    Toxicity(threshold=0.7),
    # Anonymize(allowed_names=["John Doe"]) # Example PII anonymization (optional)
]

# Define output scanners (optional, but good practice)
# Example: Check if the LLM refused to answer
output_scanners = [
    NoRefusal()
]

# --- Google Gemini Setup ---
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "AIzaSyBQVjoT9VUzdhCFad1Y6iiR-RqwclbQ5vg")
if not GEMINI_API_KEY:
    logging.error("FATAL: GEMINI_API_KEY environment variable not set.")
    gemini_available = False
else:
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        gemini_model = genai.GenerativeModel('gemini-2.0-flash')
        gemini_available = True
        logging.info("Google Gemini client initialized successfully.")
    except Exception as e:
        logging.error(f"Failed to initialize Google Gemini client: {e}")
        gemini_available = False

# --- Flask Routes ---

@app.route('/', methods=['GET'])
def index():
    """Renders the main page with the input form."""
    return render_template('index.html')

@app.route('/process', methods=['POST'])
def process_prompt():
    """
    Receives the prompt, scans it with LLM Guard, processes it with Gemini
    if safe, scans the output, and returns the result.
    """
    original_prompt = request.form.get('prompt', '')
    if not original_prompt:
        return render_template('index.html', status="Error", result="Prompt cannot be empty.", original_prompt="")

    logging.info(f"Received prompt: {original_prompt[:100]}...") # Log truncated prompt

    # 1. --- Scan the Input Prompt ---
    try:
        sanitized_prompt, results_valid, results_score = scan_prompt(input_scanners, original_prompt)
        
        # FIXED: Corrected interpretation of results_valid
        # In LLM Guard, TRUE in results_valid means the content PASSED that scanner's check
        # We need to look for FALSE values to identify failed scanners
        failed_scanners = {scanner: results_score[scanner] for scanner, is_valid in results_valid.items() if not is_valid}
        is_valid = len(failed_scanners) == 0
        
        logging.info(f"LLM Guard input scan results: Valid={is_valid}, Scores={results_score}")

        if not is_valid:
            logging.warning(f"Prompt blocked by LLM Guard. Issues: {failed_scanners}")
            return render_template('index.html',
                                   original_prompt=original_prompt,
                                   status="Blocked",
                                   scan_results=f"Issues detected: {failed_scanners}",
                                   result="Input prompt violates security policies and was blocked.")

    except Exception as e:
        logging.error(f"Error during LLM Guard input scan: {e}")
        return render_template('index.html',
                               original_prompt=original_prompt,
                               status="Error",
                               result=f"An error occurred during input security scan: {e}")

    # 2. --- Interact with Google Gemini (if input is valid) ---
    if not gemini_available:
         logging.error("Google Gemini client not available.")
         return render_template('index.html',
                               original_prompt=original_prompt,
                               status="Error",
                               scan_results=f"Input Scan Passed. Scores: {results_score}",
                               result="Google Gemini client is not configured or failed to initialize.")

    try:
        logging.info("Sending safe prompt to Google Gemini...")
        
        # Call Gemini API
        response = gemini_model.generate_content(original_prompt)
        llm_output = response.text
        logging.info("Received response from Google Gemini.")

    except Exception as e:
        logging.error(f"Google Gemini API error: {e}")
        return render_template('index.html',
                               original_prompt=original_prompt,
                               status="Error",
                               scan_results=f"Input Scan Passed. Scores: {results_score}",
                               result=f"An error occurred while communicating with Google Gemini: {e}")


    # 3. --- Scan the Output (Optional but recommended) ---
    try:
        sanitized_output, results_valid, results_score = scan_output(output_scanners, original_prompt, llm_output)
        
        # FIXED: Apply the same corrected logic to output scanning
        # Looking for FALSE values to identify failed scanners
        output_failed_scanners = {scanner: results_score[scanner] for scanner, is_valid in results_valid.items() if not is_valid}
        is_output_valid = len(output_failed_scanners) == 0

        logging.info(f"LLM Guard output scan results: Valid={is_output_valid}, Scores={results_score}")

        if not is_output_valid:
            logging.warning(f"LLM output flagged by LLM Guard. Issues: {output_failed_scanners}")
            # Decide how to handle flagged output (e.g., replace, warn, block)
            # For this example, we'll just show the original output but add a warning
            final_result = f"LLM Output (Warning - Flagged by Output Scanners: {output_failed_scanners}):\n---\n{llm_output}"
        else:
            final_result = llm_output # Use the original LLM output if it passed the scan

    except Exception as e:
        logging.error(f"Error during LLM Guard output scan: {e}")
        # Fallback: Show the raw LLM output with an error message about the scan
        final_result = f"Error during output security scan: {e}\n---\nRaw LLM Output:\n{llm_output}"


    # 4. --- Render the final result ---
    return render_template('index.html',
                           original_prompt=original_prompt,
                           status="Allowed",
                           scan_results=f"Input Scan Passed. Scores: {results_score}", # Show input scores even if passed
                           result=final_result)


# --- Main Execution ---
if __name__ == '__main__':
    # Set debug=False for production
    app.run(debug=True, port=5001) # Use a different port if 5000 is common