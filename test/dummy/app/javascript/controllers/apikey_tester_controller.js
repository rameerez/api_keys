// Connects to data-controller="apikey-tester"
import { Controller } from "@hotwired/stimulus";

export default class extends Controller {
  static targets = [
    "tokenInput", // Input field for the API key token
    "output", // <pre> tag to display the JSON result
    "testedUrl", // <code> tag to show which URL was tested
    "sendMethodInput", // Radio buttons for send method (header/query)
    "curlOutput", // <pre> tag for the cURL command equivalent
  ];

  connect() {
    console.log("ApiKeyTesterController connected.");
    this.updateCurlDisplay(); // Initialize curl display on connect
  }

  // --- Action Method --- //

  async testAction(event) {
    event.preventDefault(); // Prevent default button behavior

    const button = event.currentTarget;
    const url = button.dataset.apikeyTesterUrlParam;
    const method = button.dataset.apikeyTesterMethodParam || "GET"; // Default to GET if not specified
    const token = this.tokenInputTarget.value.trim();
    const sendMethod = this.selectedSendMethod;

    this.outputTarget.textContent = `⏳ Testing ${method} ${url} via ${sendMethod}...`;
    this.testedUrlTarget.textContent = `${method} ${url}`;
    this.updateCurlDisplay(url, method, token, sendMethod); // Update curl display before fetch

    // Determine if token is strictly required (non-public endpoints)
    const requiresToken = !url.includes("/public");

    if (requiresToken && !token) {
      this.outputTarget.textContent = `❌ Error: API Key Token required for ${method} ${url}.`;
      this.outputTarget.style.color = "red";
      return;
    }

    // Prepare Fetch Options
    const fetchOptions = {
      method: method,
      headers: {
        // "Content-Type": "application/json", // Only needed for POST/PUT/PATCH with body
        Accept: "application/json",
        // Add CSRF token only for non-GET requests for security
        ...(method !== "GET" && { "X-CSRF-Token": this.csrfToken }),
      },
      // body: JSON.stringify({ key: "value" }) // Example if body is needed
    };

    let finalUrl = url;

    // Add authentication based on selected method
    if (token) {
      // Add token if provided, even for public (server should ignore)
      if (sendMethod === "header") {
        fetchOptions.headers["Authorization"] = `Bearer ${token}`;
      } else if (sendMethod === "query") {
        // Basic query param addition - assumes no existing query params in test URLs
        finalUrl = `${url}?api_key=${encodeURIComponent(token)}`;
      }
    }

    // Perform Fetch
    try {
      const response = await fetch(finalUrl, fetchOptions);
      const data = await response.json().catch((err) => {
        console.error(
          "Failed to parse JSON response:",
          err,
          "Response Text:",
          response.text()
        );
        // Return an error structure that displayResult can handle
        return {
          status: "error",
          message: `Request failed with status ${response.status}. Response body was not valid JSON.`,
        };
      });

      this.displayResult(response, data);
    } catch (error) {
      console.error(`Error testing ${url}:`, error);
      this.outputTarget.textContent = `❌ Network/Request Error: ${error.message}`;
      this.outputTarget.style.color = "red";
    }
  }

  // --- UI Update Methods --- //

  // Updates the curl command display area
  updateCurlDisplay(
    url = null,
    method = null,
    token = null,
    sendMethod = null
  ) {
    const currentUrl = url || "/demo_api/...";
    const currentMethod = method || "GET";
    const currentToken =
      token || this.tokenInputTarget.value.trim() || "YOUR_API_KEY";
    const currentSendMethod = sendMethod || this.selectedSendMethod;

    let curlCommand = `curl -X ${currentMethod}`;

    // Base URL construction
    const baseUrl = window.location.origin;
    let fullUrl = `${baseUrl}${currentUrl}`;

    // Add headers
    curlCommand += ` \
  -H "Accept: application/json"`;
    // curlCommand += ` \
    // -H "Content-Type: application/json"`; // Only needed for POST/PUT/PATCH with body

    // Add CSRF token header only for non-GET requests
    const csrf = this.csrfToken;
    if (currentMethod !== "GET" && csrf) {
      curlCommand += ` \
  -H "X-CSRF-Token: ${csrf}"`;
    }

    // Add token based on method
    const isPublic = currentUrl.includes("/public");
    if (!isPublic && currentToken !== "YOUR_API_KEY") {
      if (currentSendMethod === "header") {
        curlCommand += ` \
  -H "Authorization: Bearer ${currentToken}"`;
      } else if (currentSendMethod === "query") {
        fullUrl += `${
          fullUrl.includes("?") ? "&" : "?"
        }api_key=${encodeURIComponent(currentToken)}`;
      }
    }

    // Add URL last
    curlCommand += ` \
  "${fullUrl}"`;

    // Add optional body hint for relevant methods
    if (["POST", "PUT", "PATCH"].includes(currentMethod)) {
      curlCommand += ` \
  -H "Content-Type: application/json" \
  -d '{"key":"value"}' # Optional request body`;
    }

    this.curlOutputTarget.textContent = curlCommand;
  }

  // Displays the fetch result in the output area
  displayResult(response, data) {
    this.outputTarget.style.color = "inherit"; // Reset color
    let outputMessage = `HTTP Status: ${response.status}\n\n`;

    try {
      // Attempt to pretty-print the JSON response body
      outputMessage += JSON.stringify(data, null, 2);
    } catch (e) {
      // Fallback if data is not valid JSON (e.g., plain text error)
      outputMessage += data.toString();
    }

    // Add a visual indicator based on status
    if (response.ok) {
      outputMessage =
        `✅ Success (${response.status})\n\n` +
        outputMessage.substring(outputMessage.indexOf("\n") + 2);
      this.outputTarget.style.color = "green";
    } else if (response.status === 401 || response.status === 403) {
      outputMessage =
        `❌ Error (${response.status})\n\n` +
        outputMessage.substring(outputMessage.indexOf("\n") + 2);
      this.outputTarget.style.color = "red";
    } else {
      outputMessage =
        `⚠️ Response (${response.status})\n\n` +
        outputMessage.substring(outputMessage.indexOf("\n") + 2);
      this.outputTarget.style.color = "orange";
    }

    this.outputTarget.textContent = outputMessage;
  }

  // --- Helpers --- //

  // Gets the selected value from the radio button group
  get selectedSendMethod() {
    return (
      this.sendMethodInputTargets.find((radio) => radio.checked)?.value ||
      "header"
    );
  }

  // Gets the CSRF token from the meta tag in the document head
  get csrfToken() {
    const tokenElement = document.head.querySelector("meta[name='csrf-token']");
    return tokenElement ? tokenElement.content : null;
  }
}
