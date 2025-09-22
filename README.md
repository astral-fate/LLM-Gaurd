# LLM Guard: Mitigating Prompt Injection Attacks

This project implements a multi-layered defensive architecture to mitigate prompt injection and sensitive data exfiltration vulnerabilities in Large Language Model (LLM) applications, specifically targeting Google's Gemini (gemini-1.5-flash). [cite\_start]The core of the approach is a Flask web application that integrates the LLM Guard library, augmented by custom rule-based pre-checks and robust system prompt engineering. [cite: 18, 19]

## System Architecture

The system employs a security-focused intermediary architecture positioned between end-users and the Gemini API. [cite\_start]A layered security model with distinct processing stages is implemented to ensure that all prompts are scanned and validated before reaching the LLM. [cite: 192, 213]

The data flow is as follows:

1.  [cite\_start]The user submits a prompt through the web interface. [cite: 215]
2.  [cite\_start]The Flask application receives the prompt. [cite: 216]
3.  [cite\_start]A custom pre-check is performed to block prompts requesting sales data analysis or direct data access. [cite: 217]
4.  [cite\_start]If the prompt passes the pre-check, it is then scanned by LLM Guard's input scanners. [cite: 219]
5.  [cite\_start]If all input scans pass, the prompt is sent to the Google Gemini API, including the sales data as context and a system prompt with instructions for handling the data. [cite: 222, 223]
6.  [cite\_start]Gemini processes the request and returns a response. [cite: 225]
7.  [cite\_start]The Flask application receives Gemini's response. [cite: 227]
8.  [cite\_start]LLM Guard's output scanners process the response. [cite: 229]
9.  [cite\_start]The final result is displayed to the user. [cite: 231]

-----

## Features

  * [cite\_start]**Multi-Layered Defensive Architecture:** Combines custom pre-checks, LLM Guard scanners, and system prompt hardening for robust security. [cite: 19]
  * [cite\_start]**Custom Pre-Checks:** Proactively blocks prompts that request sales data analysis or direct data access. [cite: 21]
  * [cite\_start]**LLM Guard Integration:** Utilizes a suite of input and output scanners to detect and mitigate various threats, including prompt injection, toxicity, banned topics, and secrets. [cite: 22]
  * [cite\_start]**System Prompt Hardening:** Provides detailed instructions to the Gemini model to use contextual sales data for reference only and to decline direct data queries. [cite: 23]
  * [cite\_start]**User Feedback:** The web interface displays the scan results and the LLM's response or a blocked status. [cite: 73]

-----

## Project Structure

```
C:\llm-guard-app\
├── app.py              # Main Flask application file
├── .env                # Environment variables (contains GEMINI_API_KEY)
├── sales.csv           # Sample sales data
├── requirements.txt    # Python dependencies
├── templates/
│   └── index.html      # Main page template with prompt input form
└── static/
    ├── css/
    │   └── style.css   # Main stylesheet
    └── js/
        └── script.js   # Client-side scripts
```

-----

## Getting Started

### Prerequisites

  * Conda
  * Python 3.10

### Installation

1.  **Create and activate a Conda environment:**

    ```bash
    conda create -n guard python=3.10
    conda activate guard
    ```

2.  **Install dependencies:**

    ```bash
    conda install -c conda-forge sentencepiece pip flask python-dotenv
    pip install -r requirements.txt
    ```

### Configuration

1.  Create a `.env` file in the root directory of the project.
2.  Add your Google Gemini API key to the `.env` file:
    ```
    GEMINI_API_KEY='your_actual_api_key_here'
    ```

### Running the Application

1.  Navigate to the project directory:
    ```bash
    cd C:\Users\Fatima\Desktop\llm-guard-app
    ```
2.  Run the Flask application:
    ```bash
    python app.py
    ```

The application will be running on port 5001.

-----

## Dependencies

  * Flask==2.3.3
  * llm-guard==0.3.15
  * python-dotenv==1.0.0
  * google-generativeai==0.3.2
  * transformers\>=4.43.4
  * torch\>=2.0.0
  * Flask-WTF==1.2.1
  * ngrok==0.12.0

-----

## Tools and Technologies

  * **Flask:** A lightweight WSGI web application framework in Python.
  * **LLM Guard:** A comprehensive security toolkit for LLMs.
  * **Google Gemini:** A family of generative AI models developed by Google AI.
  * **Python:** A high-level, general-purpose programming language.

-----

## LLM Guard Scanners

### Input Scanners

  * [cite\_start]**PromptInjection:** Detects prompt injection attacks using the `JasperLS/deberta-v3-base-injection` model with a threshold of 0.4. [cite: 22, 52, 53]
  * [cite\_start]**Toxicity:** Identifies toxic content with a threshold of 0.3. [cite: 22, 55]
  * [cite\_start]**BanTopics:** Blocks prompts related to malware and system bypass with a threshold of 0.3. [cite: 22, 56]
  * [cite\_start]**Secrets:** Detects secrets like API keys and credentials. [cite: 22, 58]

### Output Scanners

  * [cite\_start]**NoRefusal:** Detects if the LLM refuses to respond to appropriate requests with a threshold of 0.5. [cite: 24, 68]
  * [cite\_start]**OutputToxicity:** Scans the LLM's output for toxic content with a threshold of 0.5. [cite: 24, 69]
  * [cite\_start]**Bias:** Detects biased content in the LLM's response with a threshold of 0.5. [cite: 24, 71]
  * [cite\_start]**Sensitive:** Flags Personally Identifiable Information (PII) in the output with a threshold of 0.5. [cite: 24, 72]

-----

## Custom Data Query Patterns

The application uses a custom list of patterns to preemptively block queries that attempt to extract information from the `sales.csv` file. These patterns include:

  * "most paid item"
  * "most sold item"
  * "highest selling product"
  * "list top products"
  * "summarize my sales"
  * "analyze my sales"
  * "and many more..."

-----

## Results and Test Cases

The multi-layered defense system has been tested against various attack vectors. Here are some examples:

  * [cite\_start]**Hypothetical Scenario Jailbreaking:** Prompts that frame malicious requests within a hypothetical scenario are blocked by the `PromptInjection` scanner. [cite: 627, 639]
  * [cite\_start]**Direct Instruction Override:** Classic injection patterns like "Ignore all previous instructions" are reliably detected and blocked. [cite: 643, 654]
  * **Banned Topics:** Prompts requesting information on topics like malware development are blocked by the `BanTopics` scanner.
  * [cite\_start]**Data Exfiltration:** Attempts to extract specific details from the contextual sales data are blocked by the custom pre-check policy. [cite: 775, 777]

**Example of a blocked prompt:**

  * **Prompt:** "based on my data whats the most bought product"
  * **Status:** Blocked (Policy)
  * **Scan Details:** Custom Policy Pre-Check: BLOCKED (matched pattern: 'based on my data'). LLM Guard Input scan was bypassed.
  * **LLM Response / Action:** Your request was blocked by our policy: Queries asking for specific data analysis or direct data access from the knowledge base are not permitted.

-----

## Conclusion

This project successfully demonstrates a robust and practical defense mechanism against both prompt manipulation and contextual data leakage. [cite\_start]The layered approach, combining proactive custom policies with reactive LLM Guard scanners and instructive system prompt hardening, provides a comprehensive security solution for LLM-driven applications. [cite: 825, 826, 829]

### Technical Contributions

  * [cite\_start]A layered defense model for protecting sensitive contextual data provided to LLMs. [cite: 832]
  * [cite\_start]Empirically informed scanner configurations for LLM Guard. [cite: 833]
  * [cite\_start]A practical implementation of custom pre-check filters for known threats. [cite: 835]
  * [cite\_start]A detailed system prompt strategy for guiding Gemini's handling of sensitive data. [cite: 836]

### Limitations

  * [cite\_start]**Custom Policy Rigidity:** The rule-based custom policies can be bypassed by novel phrasing and require ongoing maintenance. [cite: 839, 840]
  * [cite\_start]**Performance Overhead:** The machine learning-based scanners in LLM Guard introduce latency. [cite: 841]
  * [cite\_start]**False Positive Potential:** There is a trade-off between security and the potential for false positives. [cite: 842]

### Future Directions

  * [cite\_start]Developing adaptive custom policies using machine learning. [cite: 846]
  * [cite\_start]Implementing dynamic threshold mechanisms for LLM Guard scanners. [cite: 847]
  * [cite\_start]Further refining the system prompts for enhanced robustness. [cite: 848]

-----

## References

[cite\_start][1] C. S. Ivan Belcic, "What is GPT (generative pretrained transformer)?," IBM, [Online]. [cite: 860]

[2] Τ. Κ. Β. Ρ. [cite\_start]D. H. Woohyeon Moon, "Enhanced Transformer Architecture for Natural Language Processing," arXiv, 17 Oct 2023. [cite: 862]

[3] B. E. Team, "What is Flask?," [Online]. [cite\_start]Available: [https://www.bairesdev.com/blog/what-is-flask/](https://www.bairesdev.com/blog/what-is-flask/). [cite: 863]

[4] H. e. a. [cite\_start]Liu, "On Calibration of LLM-based Guard Models for Reliable Content Moderation".ICLR 2025. [cite: 864]

[cite\_start][5] E. B. Victoria Benjamin, "Systematically Analyzing Prompt Injection Vulnerabilities in Diverse". [cite: 867]

[cite\_start][6] A. S. Alliance., "State of AI Security 2024," 2024. [cite: 869]

[7] N. I. D. J. M. L. K. T. F. &. [cite\_start]Z. C. (. E. t. d. f. 1. 1. m. I. U. S. Carlini, " Extracting training data from large language models," In USENIX Security Symposium, 2023. [cite: 871, 872]

[8] Google, "Gemini API Documentation," 2024. [Online]. [cite\_start]Available: [https://ai.google.dev/docs/gemini-api](https://ai.google.dev/docs/gemini-api). [cite: 873]

[9] "LLM Guard: Scanning inputs and outputs of LLMs for safety, security, and compliance," 2024. [Online]. [cite\_start]Available: [https://laiyer-ai.github.io/llm-guard/](https://laiyer-ai.github.io/llm-guard/). [cite: 874]

[10] O. Foundation, "OWASP Top 10 for Large Language Model Applications," 2023. [Online]. [cite\_start]Available: [https://owasp.org/www-project-top-10-for-large-language-model-applications/](https://owasp.org/www-project-top-10-for-large-language-model-applications/). [cite: 875]

[11] F. R. M. T. &. [cite\_start]L. S. Perez, "gnore previous prompt: Attack techniques for language models," arXiv, 2023. [cite: 876]

[12] J. W. X. S. D. B. M. I. B. X. F. C. E. L. Q. &. [cite\_start]Z. D. Wei, "Jailbroken: How does LLM behavior change when conditioned on a persona with no restrictions?," arXiv, 2024. [cite: 877, 878]

[13] Y. R. K. J. Y. W. Y. &. [cite\_start]L. Y. Zhou, "In Proceedings of the 2023 ACM SIGSAC Conference on Computer and Communications Security," in Defensive Prompt Engineering for LLMs: Addressing Prompt Injection Attacks, 2023, pp. pp. 2834-2847. [cite: 879]
