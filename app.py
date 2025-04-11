import os
import logging
from flask import Flask, render_template, request
from dotenv import load_dotenv
import google.generativeai as genai
# --- LLM Guard Setup ---
from llm_guard.input_scanners import (
    PromptInjection,
    Toxicity,
    BanTopics,
    Secrets
    # Remove Code scanner entirely
)
from llm_guard.output_scanners import (
    NoRefusal,
    Toxicity as OutputToxicity,
    Bias
)
from llm_guard import scan_prompt, scan_output

# --- Configuration ---
load_dotenv()  # Load environment variables from .env file

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize Flask app
app = Flask(__name__)

# --- LLM Guard Setup ---

# BALANCED INPUT SCANNERS
input_scanners = [
    PromptInjection(threshold=0.3),  # Good balance of security/usability  
    Toxicity(threshold=0.3),         # Good balance of security/usability
    
    # Keep BanTopics for semantic matching of harmful content
    BanTopics(
        topics=[
            # Keep your existing topics list
            "malware", "virus", "ransomware", "trojan", "spyware", "keylogger",
            "create malware", "write malicious code", "build a virus",
            "make ransomware", "develop a trojan", "code for hacking",
            "harmful software creation", "script for computer attacks",
            "create code to steal data", "instructions for malware", "malware development",
            "hacking tutorial", "exploit development",
        ],
        threshold=0.65  # Higher threshold to prevent false positives
    ),
    
    Secrets(),
   
]


output_scanners = [
    NoRefusal(),
    OutputToxicity(threshold=0.5),   # Filter toxic responses
    Bias(threshold=0.5),             # Filter biased content
]

# --- Google Gemini Setup ---
# Use a more robust way to handle potential missing key
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
gemini_available = False
gemini_model = None

if not GEMINI_API_KEY:
    logging.warning("GEMINI_API_KEY environment variable not set. Google Gemini features will be disabled.")
else:
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        # Consider using a model known for stronger safety features if needed,
        # although 'gemini-1.5-flash' is generally good.
        gemini_model = genai.GenerativeModel('gemini-1.5-flash') 
        # Quick test call (optional, remove in production)
        # gemini_model.generate_content("test")
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

    sanitized_prompt = original_prompt # Start with original, scan_prompt overwrites if safe
    scan_results_dict = {}
    final_status = "Error" # Default status
    final_result = "An unexpected error occurred during processing."
    input_scan_details = "Scan not performed."

    # 1. --- Scan the Input Prompt ---
    try:
        sanitized_prompt, results_valid_dict, results_score_dict = scan_prompt(input_scanners, original_prompt)

        # Check if *any* scanner failed (returned False)
        failed_scanners = {scanner: results_score_dict.get(scanner, 'N/A')
                           for scanner, is_valid in results_valid_dict.items() if not is_valid}
        all_scanners_passed = len(failed_scanners) == 0
        input_scan_details = f"Results: {results_valid_dict}, Scores: {results_score_dict}" # Store details

        logging.info(f"LLM Guard input scan results: Passed={all_scanners_passed}, Scores={results_score_dict}")

        if not all_scanners_passed:
            logging.warning(f"Prompt blocked by LLM Guard. Issues: {failed_scanners}")
            final_status = "Blocked"
            final_result = "Input prompt violates security policies and was blocked."
            # No need to proceed to Gemini or output scan
            return render_template('index.html',
                                   original_prompt=original_prompt,
                                   status=final_status,
                                   scan_results=f"Input Scan Failed. Issues: {failed_scanners}. Full Scores: {results_score_dict}",
                                   result=final_result)
        else:
            # Input scan passed
            final_status = "Allowed" # Tentative status, pending LLM call and output scan
            logging.info("Input prompt passed security scan.")

    except Exception as e:
        logging.error(f"Error during LLM Guard input scan: {e}", exc_info=True)
        # Keep final_status as "Error"
        final_result = f"An error occurred during input security scan: {e}"
        input_scan_details = "Error during scan."
        return render_template('index.html',
                               original_prompt=original_prompt,
                               status=final_status,
                               scan_results=input_scan_details,
                               result=final_result)

    # 2. --- Interact with Google Gemini (Only if input scan passed) ---
    llm_output = ""
    if final_status == "Allowed": # Proceed only if input was allowed
        if not gemini_available or gemini_model is None:
             logging.error("Google Gemini client not available.")
             final_status = "Error"
             final_result = "Input scan passed, but Google Gemini client is not configured or failed to initialize."
        else:
            try:
                logging.info(f"Sending safe prompt to Google Gemini: {sanitized_prompt[:100]}...")
                # IMPORTANT: Send the SANITIZED prompt if anonymization or other modifications occurred
                response = gemini_model.generate_content(sanitized_prompt)
                # Handle potential empty or blocked responses from Gemini itself
                llm_output = response.text if hasattr(response, 'text') else "Gemini did not provide a text response."
                logging.info("Received response from Google Gemini.")

            except Exception as e:
                logging.error(f"Google Gemini API error: {e}", exc_info=True)
                final_status = "Error"
                final_result = f"Input scan passed, but an error occurred while communicating with Google Gemini: {e}"

    # 3. --- Scan the Output (If Gemini call was successful) ---
    output_scan_details = "Output scan not performed."
    if final_status == "Allowed" and llm_output: # Proceed only if input passed and we got LLM output
        try:
            # Use original_prompt for context if needed by output scanners like NoRefusal
            sanitized_output, output_results_valid, output_results_score = scan_output(
                output_scanners, original_prompt, llm_output
            )

            output_failed_scanners = {scanner: output_results_score.get(scanner, 'N/A')
                                      for scanner, is_valid in output_results_valid.items() if not is_valid}
            is_output_valid = len(output_failed_scanners) == 0
            output_scan_details = f"Results: {output_results_valid}, Scores: {output_results_score}"

            logging.info(f"LLM Guard output scan results: Valid={is_output_valid}, Scores={output_results_score}")

            if not is_output_valid:
                logging.warning(f"LLM output flagged by LLM Guard. Issues: {output_failed_scanners}")
                # Append a warning to the output rather than blocking entirely (configurable choice)
                final_result = f"LLM Output (Warning - Flagged by Output Scanners: {output_failed_scanners}):\n---\n{llm_output}"
            else:
                # Output is also valid
                final_result = llm_output # Use the original LLM output

        except Exception as e:
            logging.error(f"Error during LLM Guard output scan: {e}", exc_info=True)
            # Fallback: Show the raw LLM output with an error message about the output scan
            final_result = f"Error during output security scan: {e}\n---\nRaw LLM Output:\n{llm_output}"
            output_scan_details = "Error during output scan."


    # 4. --- Render the final result ---
    # Combine input and output scan details for clarity
    combined_scan_results = f"Input Scan: {input_scan_details}\nOutput Scan: {output_scan_details}"

    return render_template('index.html',
                           original_prompt=original_prompt,
                           status=final_status, # Reflects the final outcome (Blocked, Allowed, Error)
                           scan_results=combined_scan_results,
                           result=final_result)


# --- Main Execution ---
if __name__ == '__main__':

    app.run(host='0.0.0.0', port=5001, debug=True)
