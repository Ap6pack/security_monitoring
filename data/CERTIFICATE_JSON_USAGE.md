# Certificate JSON File Usage

If you encounter rate limiting from crt.sh (429 errors), you can manually download the certificate data and use it as a fallback:

1. Open your browser and visit: <https://crt.sh/json?q=yourdomain.com>
2. Save the JSON response to a file (e.g., data/crtsh_yourdomain.json)
3. Set the environment variable:
   export CERTIFICATE_JSON_FILE=data/crtsh_yourdomain.json
4. Run the scan - it will use the file instead of querying the API

The scanner will automatically fall back to the API if the file is missing or invalid.
