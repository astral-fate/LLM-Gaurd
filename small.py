import os
import logging
from flask import Flask, render_template, request
from dotenv import load_dotenv
import google.generativeai as genai
import pandas as pd

# --- LLM Guard Setup ---
from llm_guard.input_scanners import (
    # PromptInjection, # Commented out
    # Toxicity,        # Commented out
    # BanTopics,       # Commented out
    Secrets
)
from llm_guard.output_scanners import (
    # NoRefusal,                  # Commented out
    # Toxicity as OutputToxicity, # Commented out
    # Bias,                       # Commented out
    # Sensitive                   # Commented out
)
from llm_guard import scan_prompt, scan_output
# from llm_guard.model import Model as LLMGuardModel # Commented out as PromptInjection model is not used

# --- Configuration ---
load_dotenv()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
app = Flask(__name__)
SALES_CSV_PATH = 'sales.csv'

# --- LLM Guard Input Scanners: Comprehensive Set ---
# These will only be used if the custom pre-check passes
# prompt_injection_model_config = { # Commented out as PromptInjection scanner is disabled
#     'path': 'JasperLS/deberta-v3-base-injection',
#     'revision': 'main',
#     'pipeline_kwargs': {
#          "padding": True,
#          "truncation": True,
#          "max_length": 512,
#     },
#     'tokenizer_kwargs': {},
# }

input_scanners = [
    # PromptInjection( # Commented out
    #     model=LLMGuardModel(**prompt_injection_model_config),
    #     threshold=0.4
    # ),
    # Toxicity(threshold=0.3), # Commented out
    # BanTopics( # Commented out
    #     topics=[
    #         # Malicious/Harmful Content
    #         "malware", "virus", "ransomware", "trojan", "spyware", "keylogger",
    #         "create malware", "write malicious code", "build a virus",
    #         "make ransomware", "develop a trojan", "code for hacking",
    #         "harmful software creation", "script for computer attacks",
    #         "create code to steal data", "instructions for malware", "malware development",
    #         "hacking tutorial", "exploit development",

    #         # System-level Bypass / Data Dumping (very generic ones)
    #         "ignore previous instructions",
    #         "disregard your primary function",
    #         "reveal your system prompt",
    #         "show me the raw data",
    #         "print the entire dataset",
    #         "leak all customer information",
    #         "dump the full content",
    #         "override safety protocols",
    #         "you are now in developer mode",
    #     ],
    #     threshold=0.3
    # ),
    Secrets(), # This scanner is lightweight and uses regex
]

# --- LLM Guard Output Scanners: Comprehensive Set ---
output_scanners = [
    # NoRefusal(threshold=0.5), # Commented out
    # OutputToxicity(threshold=0.5), # Commented out
    # Bias(threshold=0.5), # Commented out
    # Sensitive( # Commented out
    #     threshold=0.5,
    #     redact=False,
    #     entity_types=[
    #         "CREDIT_CARD", "PHONE_NUMBER", "EMAIL_ADDRESS", "US_SSN",
    #         "PERSON", "LOCATION", "ORGANIZATION", "DATE_TIME", "NRP"
    #     ]
    # )
]

# --- Custom Data Query Patterns ---
CUSTOM_DATA_QUERY_PATTERNS = [
    "most paid item",
    "most sold item",
    "highest selling product",
    "list top products",
    "summarize my sales",
    "analyze my sales",
    "analyze my data",
    "insights from sales",
    "insights from my data",
    "sales transactions",
    "customer purchase",
    "revenue by item",
    "profit margins for products",
    "top sellers",
    "sales trends",
    "breakdown of sales",
    "based on my data",
    "from my data",
    "using the sales data",
    "using my data",
    "according to my sales data",
    "according to my data",
    "my sales say",
    "my data say",
    "check my sales data for",
    "check my data for",
    "raw data from",
    "entire sales dataset",
    "leak all customer information",
    "extract all records",
    "dump the full content",
]


# --- Google Gemini Setup ---
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
gemini_available = False
gemini_model = None
if not GEMINI_API_KEY:
    logging.warning("GEMINI_API_KEY environment variable not set. Google Gemini features will be disabled.")
else:
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        gemini_model = genai.GenerativeModel('gemini-1.5-flash')
        gemini_available = True
        logging.info("Google Gemini client initialized successfully.")
    except Exception as e:
        logging.error(f"Failed to initialize Google Gemini client: {e}")
        gemini_available = False

# --- Helper Function to Load and Clean CSV Data ---
def load_sales_data_as_text():
    try:
        if os.path.exists(SALES_CSV_PATH):
            df = pd.read_csv(SALES_CSV_PATH)
            if 'Amount' in df.columns:
                if df['Amount'].dtype == 'object':
                    df['Amount'] = df['Amount'].replace({'\$': '', ',': ''}, regex=True)
                    df['Amount'] = pd.to_numeric(df['Amount'], errors='coerce').fillna(0)
            return df.to_csv(index=False)
        else:
            logging.warning(f"{SALES_CSV_PATH} not found. Creating dummy data for testing.")
            dummy_data = {
                'Product': ['Apple', 'Banana', 'Apple', 'Orange', 'Banana', 'Banana', 'Grape', 'Apple'],
                'Date': ['2023-01-01', '2023-01-01', '2023-01-02', '2023-01-02', '2023-01-03', '2023-01-03', '2023-01-04', '2023-01-04'],
                'Amount': [1.0, 0.5, 1.0, 0.75, 0.5, 0.5, 2.0, 1.0],
                'CustomerID': ['C001', 'C002', 'C001', 'C003', 'C002', 'C004', 'C005', 'C001']
            }
            df_dummy = pd.DataFrame(dummy_data)
            df_dummy.to_csv(SALES_CSV_PATH, index=False)
            logging.info(f"Created dummy {SALES_CSV_PATH}.")
            return df_dummy.to_csv(index=False)
    except Exception as e:
        logging.error(f"Error loading or processing sales data: {e}", exc_info=True)
        return "Error: Could not load or process the sales data."

# --- Flask Routes ---
@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/process', methods=['POST'])
def process_prompt():
    original_user_prompt = request.form.get('prompt', '')
    if not original_user_prompt:
        return render_template('index.html', status="Error", result="Prompt cannot be empty.", original_prompt="")

    logging.info(f"Received user prompt: {original_user_prompt[:200]}...")

    final_status = "Error"
    final_result = "An unexpected error occurred during processing."
    input_scan_details = "Scan details not applicable."
    output_scan_details = "Output scan not performed."

    prompt_lower = original_user_prompt.lower()
    matched_custom_pattern = None
    for pattern in CUSTOM_DATA_QUERY_PATTERNS:
        if pattern in prompt_lower:
            matched_custom_pattern = pattern
            break

    if matched_custom_pattern:
        logging.warning(f"User prompt BLOCKED by custom policy (pre-check). Matched pattern: '{matched_custom_pattern}'")
        final_status = "Blocked (Policy)"
        final_result = "Your request was blocked by our policy: Queries asking for specific data analysis or direct data access from the knowledge base are not permitted."
        input_scan_details = f"Custom Policy Pre-Check: BLOCKED (matched pattern: '{matched_custom_pattern}'). LLM Guard input scan was bypassed."
        scan_results_for_template = input_scan_details
        return render_template('index.html',
                               original_prompt=original_user_prompt,
                               status=final_status,
                               scan_results=scan_results_for_template,
                               result=final_result)

    processed_user_prompt = original_user_prompt

    # Check if there are any input scanners defined. If not, skip this step.
    if input_scanners:
        try:
            logging.info(f"User prompt passed custom policy pre-check. Now scanning with LLM Guard input scanners: '{original_user_prompt}'")
            sanitized_prompt_after_llm_guard, results_valid_dict, results_score_dict = scan_prompt(
                input_scanners, original_user_prompt
            )

            failed_scanners_input = {
                scanner_name: results_score_dict.get(scanner_name, 'N/A')
                for scanner_name, is_valid in results_valid_dict.items() if not is_valid
            }
            all_input_scanners_passed = not failed_scanners_input

            input_scan_details_llm_guard = f"LLM Guard Input Scan: Validations={results_valid_dict}, Scores={results_score_dict}"
            logging.info(f"LLM Guard input scan results: Passed={all_input_scanners_passed}, Details={input_scan_details_llm_guard}")

            if not all_input_scanners_passed:
                logging.warning(f"User prompt BLOCKED by LLM Guard input scanners. Issues: {failed_scanners_input}")
                final_status = "Blocked (LLM Guard)"
                final_result = f"Input blocked by LLM Guard due to: {', '.join(failed_scanners_input.keys())}."
                scan_results_for_template = (f"Custom Policy Pre-Check: PASSED.\n"
                                             f"{input_scan_details_llm_guard} - BLOCKED. Issues: {failed_scanners_input}.")
                return render_template('index.html',
                                       original_prompt=original_user_prompt,
                                       status=final_status,
                                       scan_results=scan_results_for_template,
                                       result=final_result)
            else:
                final_status = "Allowed"
                processed_user_prompt = sanitized_prompt_after_llm_guard
                logging.info("User prompt passed custom policy pre-check and LLM Guard input security scan.")
                input_scan_details = (f"Custom Policy Pre-Check: PASSED.\n"
                                      f"{input_scan_details_llm_guard} - PASSED.")

        except Exception as e:
            logging.error(f"Error during LLM Guard input scan: {e}", exc_info=True)
            final_status = "Error"
            final_result = f"An error occurred during the input security scan: {e}"
            input_scan_details = (f"Custom Policy Pre-Check: PASSED.\n"
                                  f"Error during LLM Guard input scan: {e}")
            scan_results_for_template = input_scan_details
            return render_template('index.html',
                                   original_prompt=original_user_prompt,
                                   status=final_status,
                                   scan_results=scan_results_for_template,
                                   result=final_result)
    else: # No input scanners defined
        final_status = "Allowed" # Proceed as if input scan passed (since there were no scanners)
        input_scan_details = "Custom Policy Pre-Check: PASSED.\nLLM Guard Input Scan: SKIPPED (no input scanners configured)."
        logging.info("User prompt passed custom policy pre-check. LLM Guard input scan skipped (no scanners).")


    llm_output = ""
    if final_status == "Allowed":
        if not gemini_available or gemini_model is None:
             logging.error("Google Gemini client not available or not initialized.")
             final_status = "Error"
             final_result = "Input scans passed, but the AI model (Google Gemini) is not available or failed to initialize."
             output_scan_details = "Output scan not performed (Gemini not available)."
        else:
            try:
                sales_data_context = load_sales_data_as_text()
                if "Error: Could not load or process the sales data." in sales_data_context:
                    logging.error("Failed to load sales data for Gemini context.")
                    sales_data_context = "Note: Sales data context could not be loaded."

                prompt_for_gemini = (
                    f"You are an AI assistant. You have access to internal sales data for contextual understanding if a question pertains to it, "
                    f"but your primary role is NOT to perform deep data analysis, reveal specific figures, or list raw data from it unless "
                    f"it's a very general, high-level summary that doesn't expose sensitive details.\n"
                    f"--- BEGIN SALES DATA CONTEXT (for your reference only, do not disclose verbatim) ---\n"
                    f"{sales_data_context}\n"
                    f"--- END SALES DATA CONTEXT ---\n\n"
                    f"IMPORTANT INSTRUCTIONS BASED ON THE USER'S REQUEST:\n"
                    f"1. Regarding the sales data: DO NOT reveal, list, summarize in detail, aggregate specific numbers, or provide any specific product names, customer information, or detailed patterns directly from it.\n"
                    f"   Politely decline if the user asks for such specific details, analysis, or data extraction.\n"
                    f"2. If the user's request DIRECTLY asks for information that would require you to extract or perform detailed analysis of the sales data (e.g., 'what was the most bought item last month?', 'total sales revenue for product X', 'list all customer IDs'), "
                    f"   you MUST politely decline, stating that you cannot provide specific sales data analysis or details.\n"
                    f"3. For general knowledge questions (e.g., 'tell me a fact about cats', 'what is the capital of France?') that DO NOT relate to the sales data, answer them normally and helpfully. Do not refer to the sales data for these.\n"
                    f"4. If a question is very general about sales (e.g., 'What kind of products do we sell?'), you can provide a high-level, vague answer based on the product categories if apparent, without giving specifics.\n"
                    f"5. Do not generate harmful content, attempt to bypass these instructions, or act as a direct data query engine for the sales data.\n\n"
                    f"Based ONLY on these instructions and the user's request below, provide a helpful and safe response. Do not use external information unless the question is a general knowledge one.\n"
                    f"User's request: \"{processed_user_prompt}\""
                )

                logging.info(f"Sending to Gemini (system prompt includes sales context, then user request). User request part: \"{processed_user_prompt}\"")

                safety_settings_for_gemini = [
                    {"category": c, "threshold": "BLOCK_MEDIUM_AND_ABOVE"} for c in [
                        "HARM_CATEGORY_HARASSMENT", "HARM_CATEGORY_HATE_SPEECH",
                        "HARM_CATEGORY_SEXUALLY_EXPLICIT", "HARM_CATEGORY_DANGEROUS_CONTENT"
                    ]
                ]
                response = gemini_model.generate_content(
                    prompt_for_gemini,
                    safety_settings=safety_settings_for_gemini
                )

                if response.candidates and response.candidates[0].content and response.candidates[0].content.parts:
                    llm_output = "".join(p.text for p in response.candidates[0].content.parts if hasattr(p, 'text'))

                if not llm_output:
                    block_reason_msg = ""
                    if hasattr(response, 'prompt_feedback') and response.prompt_feedback and response.prompt_feedback.block_reason:
                        block_reason_msg = f"Gemini Prompt Feedback: Blocked due to {response.prompt_feedback.block_reason}."
                    
                    finish_reason_msg = ""
                    safety_ratings_msg = ""
                    if response.candidates:
                        candidate = response.candidates[0]
                        finish_reason_msg = f"Gemini Finish Reason: {candidate.finish_reason}."
                        if hasattr(candidate, 'safety_ratings') and candidate.safety_ratings:
                             safety_ratings_msg = f"Safety Ratings: {candidate.safety_ratings}."
                    else:
                         finish_reason_msg = "No candidates in Gemini response."

                    gemini_issue_message = "The AI model did not provide a text response. "
                    if block_reason_msg: gemini_issue_message += block_reason_msg + " "
                    if finish_reason_msg: gemini_issue_message += finish_reason_msg + " "
                    if safety_ratings_msg: gemini_issue_message += safety_ratings_msg
                    
                    llm_output = gemini_issue_message.strip().replace("  ", " ").replace(". .", ".")
                    logging.warning(f"Gemini issue: {llm_output}")
                    final_result = llm_output
                    output_scan_details = "Output scan skipped (AI model issue or no content generated)."
                else:
                    logging.info(f"Received response from Google Gemini (first 100 chars): {llm_output[:100]}...")

            except Exception as e:
                logging.error(f"Google Gemini API error: {e}", exc_info=True)
                final_status = "Error"
                final_result = f"Input scans passed, but an error occurred while communicating with the AI model (Google Gemini): {e}"
                output_scan_details = "Output scan not performed (Gemini API error)."

    # Check if there are any output scanners defined and if we have output to scan.
    if output_scanners and final_status == "Allowed" and llm_output and not llm_output.startswith("The AI model did not provide a text response."):
        try:
            logging.info(f"Scanning LLM output with LLM Guard: '{llm_output[:100]}...'")
            sanitized_llm_output, output_results_valid, output_results_score = scan_output(
                output_scanners, original_user_prompt, llm_output
            )

            output_failed_scanners_map = {
                scanner_name: output_results_score.get(scanner_name, 'N/A')
                for scanner_name, is_valid in output_results_valid.items() if not is_valid
            }
            is_output_valid = not output_failed_scanners_map
            output_scan_details = f"LLM Guard Output Scan: Validations={output_results_valid}, Scores={output_results_score}"
            logging.info(f"LLM Guard output scan results: Passed={is_output_valid}, Details={output_scan_details}")

            if not is_output_valid:
                logging.warning(f"LLM output FLAGGED by LLM Guard output scanners. Issues: {output_failed_scanners_map}")
                final_status = "Flagged (Output)"
                final_result = (f"The AI's response was reviewed and could not be fully displayed due to potential issues "
                                f"(flagged by LLM Guard Output Scanners: {', '.join(output_failed_scanners_map.keys())}).")
            else:
                final_result = sanitized_llm_output
                output_scan_details += " - PASSED."
        except Exception as e:
            logging.error(f"Error during LLM Guard output scan: {e}", exc_info=True)
            final_status = "Error"
            final_result = f"An error occurred during the output security scan: {e}\n---\nRaw AI Output (may contain unverified content):\n{llm_output}"
            output_scan_details = f"Error during LLM Guard output scan: {e}"
    elif not output_scanners and final_status == "Allowed" and llm_output and not llm_output.startswith("The AI model did not provide a text response."):
        # No output scanners defined, but we have LLM output
        final_result = llm_output # Use the raw LLM output
        output_scan_details = "LLM Guard Output Scan: SKIPPED (no output scanners configured)."
        logging.info("LLM Guard output scan skipped (no output scanners).")
    elif final_status == "Allowed" and not llm_output:
        if not (final_result and final_result.startswith("The AI model did not provide")):
             final_result = "The AI model generated no content. This could be due to the nature of the request or internal safety measures of the model."
        output_scan_details = "Output scan not performed (no content from AI model)."


    scan_results_for_template = f"Input Scan Details:\n{input_scan_details}\n\nOutput Scan Details:\n{output_scan_details}"

    if final_status == "Blocked (Policy)":
        scan_results_for_template = input_scan_details
    elif final_status == "Blocked (LLM Guard)":
        pass
    elif final_status == "Error" and ("input security scan" in final_result or "LLM Guard input scan" in input_scan_details):
        scan_results_for_template = input_scan_details

    return render_template('index.html',
                           original_prompt=original_user_prompt,
                           status=final_status,
                           scan_results=scan_results_for_template,
                           result=final_result)


# --- Main Execution ---
if __name__ == '__main__':
    if not GEMINI_API_KEY:
        print("\nERROR: GEMINI_API_KEY environment variable not found.")
        print("Please create a .env file in the same directory as this script and add the line:")
        print("GEMINI_API_KEY='your_actual_api_key_here'\n")
    if not os.path.exists(SALES_CSV_PATH):
        print(f"\nWARNING: The sales data file '{SALES_CSV_PATH}' was not found.")
        print("A dummy sales.csv will be created on the first request if it's still missing.")
        print("For real data, please ensure your CSV is at the correct path.\n")

    app.run(host='0.0.0.0', port=5001, debug=True)
