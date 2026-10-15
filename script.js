// Phishing Detection System
// Rule-based URL analysis for cybersecurity education only.

const form = document.getElementById("phishing-form");
const urlInput = document.getElementById("url-input");
const loadingState = document.getElementById("loading-state");
const resultsSection = document.getElementById("results");
const inputFeedback = document.getElementById("input-feedback");
const scoreValue = document.getElementById("score-value");
const scoreText = document.getElementById("score-text");
const scoreCircle = document.getElementById("score-circle");
const overallStatus = document.getElementById("overall-status");
const analyzedUrl = document.getElementById("analyzed-url");
const statusBadge = document.getElementById("result-status-badge");
const failedList = document.getElementById("failed-list");
const scoreCard = document.getElementById("score-card");
const failedCard = document.getElementById("failed-card");

const suspiciousKeywords = [
  "verify",
  "update",
  "password",
  "account",
  "secure",
  "bank",
];
const suspiciousTlds = [
  ".zip",
  ".review",
  ".country",
  ".kim",
  ".cricket",
  ".work",
  ".tk",
  ".gq",
  ".ml",
  ".cf",
  ".exe",
];
const protectedBrands = [
  "facebook",
  "google",
  "amazon",
  "microsoft",
  "apple",
  "paypal",
  "instagram",
  "netflix",
  "youtube",
  "uit",
  "cisco",
];
const shorteningServices = [
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "ow.ly",
  "is.gd",
  "buff.ly",
  "rebrand.ly",
  "cutt.ly",
  "shorturl.at",
];


form.addEventListener("submit", (event) => {
  event.preventDefault();

  const originalInput = urlInput.value.trim();

  if (!originalInput) {
    showInputError("Please enter a URL to analyze.");
    return;
  }

  if (
    !originalInput.startsWith("http://") &&
    !originalInput.startsWith("https://")
  ) {
    showInputError("Protocol Error: URL must start with http:// or https://");
    return;
  }

  if (originalInput.startsWith("http://")) {
    showInputError(
      "Security Warning: http:// is unsecure. We strongly recommend using https:// instead.",
    );
    //return;
  }

  const parsedUrl = safeParseUrl(originalInput);
  if (!parsedUrl) {
    showInputError("Please enter a valid URL. Example: https://example.com");
    return;
  }

  clearInputError();
  startLoading();

  window.setTimeout(() => {
    const result = analyzeUrl(originalInput, parsedUrl);
    renderResults(result);
    stopLoading();
  }, 900);
});

function safeParseUrl(value) {
  const candidateUrl = createParsableUrl(value);

  try {
    return new URL(candidateUrl);
  } catch (error) {
    return null;
  }
}

function createParsableUrl(value) {
  if (/^https?:\/\//i.test(value)) {
    return value;
  }

  if (/^https?\/\//i.test(value)) {
    return value.replace(/^(https?)\/\//i, "$1://");
  }

  if (/^https?:\//i.test(value)) {
    return value.replace(/^(https?):\//i, "$1://");
  }

  return `https://${value}`;
}

function analyzeUrl(originalInput, urlObject) {
  const scoreItems = [];
  const failedChecks = [];

  const hostname = urlObject.hostname.toLowerCase();
  const inputText = originalInput.toLowerCase();
  const hasExplicitHttp = /^http(?::\/\/|\/)/i.test(originalInput);
  const isIpAddress = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  const hasAtSymbol = originalInput.includes("@");
  const hasHyphenInDomain = hostname.includes("-");
  const hostnameParts = hostname.split(".").filter(Boolean);
  // const subdomainCount = Math.max(hostnameParts.length - 2, 0);
  const subdomainCount = isIpAddress
    ? 0
    : Math.max(hostnameParts.length - 2, 0);
  const isShortened = shorteningServices.some(
    (service) => hostname === service || hostname.endsWith(`.${service}`),
  );
  const urlLength = originalInput.length;
  const keywordMatches = suspiciousKeywords.filter((keyword) =>
    inputText.includes(keyword),
  );
  const obfuscatedKeywordMatches = [];

  if (/l0gin/i.test(inputText)) {
    obfuscatedKeywordMatches.push("l0gin");
  }

  if (/log1n/i.test(inputText)) {
    obfuscatedKeywordMatches.push("log1n");
  }

  if (/s1gn1n/i.test(inputText)) {
    obfuscatedKeywordMatches.push("s1gn1n");
  }

  if (/s1gnin/i.test(inputText)) {
    obfuscatedKeywordMatches.push("s1gnin");
  }

  if (/sign1n/i.test(inputText)) {
    obfuscatedKeywordMatches.push("sign1n");
  }

  if (/l0g1n/i.test(inputText)) {
    obfuscatedKeywordMatches.push("l0g1n");
  }

  if (/passw0rd/i.test(inputText)) {
    obfuscatedKeywordMatches.push("passw0rd");
  }

  if (/acc0unt/i.test(inputText)) {
    obfuscatedKeywordMatches.push("acc0unt");
  }

  if (/ver1fy/i.test(inputText)) {
    obfuscatedKeywordMatches.push("ver1fy");
  }

  if (/secur1ty/i.test(inputText)) {
    obfuscatedKeywordMatches.push("secur1ty");
  }
  const matchedTld = suspiciousTlds.find((tld) => hostname.endsWith(tld));
  const spoofedBrand = detectBrandSpoof(hostname);

  addCheckResult({
    condition: hasExplicitHttp,
    points: 20,
    failMessage: "URL does not use HTTPS.",
    scoreItems,
    failedChecks,
  });

  addCheckResult({
    condition: isIpAddress,
    points: 30,
    failMessage: "IP address is used instead of a domain name.",
    scoreItems,
    failedChecks,
  });

  addCheckResult({
    condition: hasAtSymbol,
    points: 25,
    failMessage:
      "URL contains the '@' symbol, which can hide the true destination.",
    scoreItems,
    failedChecks,
  });

  addCheckResult({
    condition: hasHyphenInDomain,
    points: 10,
    failMessage:
      "Domain contains a hyphen, which is sometimes used in deceptive lookalike domains.",
    scoreItems,
    failedChecks,
  });

  addCheckResult({
    condition: subdomainCount >= 2,
    points: 10,
    failMessage: `URL contains many subdomains (${subdomainCount}), which can make it look misleading.`,
    scoreItems,
    failedChecks,
  });

  addCheckResult({
    condition: isShortened,
    points: 20,
    failMessage:
      "URL uses a shortening service that can hide the final destination.",
    scoreItems,
    failedChecks,
  });

  addCheckResult({
    condition: urlLength > 75,
    points: 10,
    failMessage: `URL is long (${urlLength} characters), which can hide suspicious parts.`,
    scoreItems,
    failedChecks,
  });

  addCheckResult({
    condition: keywordMatches.length > 0,
    points: 15,
    failMessage: `Suspicious keywords found: ${keywordMatches.join(", ")}.`,
    scoreItems,
    failedChecks,
  });

  addCheckResult({
    condition: Boolean(matchedTld),
    points: 15,
    failMessage: `Potentially suspicious top-level domain detected: ${matchedTld}.`,
    scoreItems,
    failedChecks,
  });

  addCheckResult({
    condition: Boolean(spoofedBrand),
    points: 25,
    failMessage: "Possible brand spoofing (lookalike domain).",
    scoreItems,
    failedChecks,
  });

  addCheckResult({
    condition: obfuscatedKeywordMatches.length > 0,
    points: 25,
    failMessage: `Obfuscated suspicious keywords found: ${obfuscatedKeywordMatches.join(", ")}.`,
    scoreItems,
    failedChecks,
  });

  const repeatedSubdomain =
    hostnameParts.length >= 3 &&
    hostnameParts[0] === hostnameParts[1];

  addCheckResult({
    condition: repeatedSubdomain,
    points: 10,
    failMessage: "Repeated subdomain detected.",
    scoreItems,
    failedChecks
  });

  const rawScore = scoreItems.reduce((total, item) => total + item.points, 0);
  const score = Math.min(rawScore, 100);

  const status = score === 0 ? "SAFE" : score <= 44 ? "SUSPICIOUS" : "UNSAFE";

  const severityClass =
    score === 0 ? "safe" : score <= 44 ? "suspicious" : "phishing";

  return {
    analyzedUrl: originalInput,
    score,
    status,
    severityClass,
    failedChecks,
  };
}

function addCheckResult({
  condition,
  points,
  failMessage,
  scoreItems,
  failedChecks,
}) {
  if (condition) {
    scoreItems.push({ points, message: `${failMessage} (+${points})` });
    failedChecks.push(failMessage);
  }
}

function detectBrandSpoof(hostname) {
  const domainLabel = getPrimaryDomainLabel(hostname);

  if (!domainLabel) {
    return null;
  }

  return (
    protectedBrands.find((brand) => isLookalikeBrand(domainLabel, brand)) ||
    null
  );
}

// function getPrimaryDomainLabel(hostname) {
//     const parts = hostname.split(".").filter(Boolean);

//     if (parts.length === 0) {
//         return "";
//     }

//     if (parts.length === 1) {
//         return parts[0];
//     }

//     return parts[parts.length - 2];
// }

function getPrimaryDomainLabel(hostname) {
  const parts = hostname.split(".").filter(Boolean);

  if (parts.length === 0) {
    return "";
  }

  // Myanmar academic domains: example.edu.mm
  if (
    parts.length >= 3 &&
    parts[parts.length - 2] === "edu" &&
    parts[parts.length - 1] === "mm"
  ) {
    return parts[parts.length - 3];
  }

  if (
    parts.length >= 3 &&
    parts[parts.length - 2] === "example" &&
    parts[parts.length - 1] === "com"
  ) {
    return parts[parts.length - 3];
  }

  if (parts.length === 1) {
    return parts[0];
  }

  return parts[parts.length - 2];
}

function isLookalikeBrand(domainLabel, brand) {
  if (domainLabel === brand) {
    return false;
  }

  const normalizedLabel = normalizeLookalikeText(domainLabel);
  const normalizedBrand = normalizeLookalikeText(brand);

  if (normalizedLabel === normalizedBrand) {
    return true;
  }

  if (
    normalizedLabel.length < 4 ||
    normalizedLabel.length !== normalizedBrand.length
  ) {
    return false;
  }

  return levenshteinDistance(normalizedLabel, normalizedBrand) === 1;
}

function normalizeLookalikeText(value) {
  const characterMap = {
    0: "o",
    1: "i",
    3: "e",
    4: "a",
    5: "s",
    7: "t",
    8: "b",
    9: "g",
    "@": "a",
    $: "s",
  };

  return value
    .toLowerCase()
    .replace(/rn/g, "m")
    .replace(/vv/g, "w")
    .split("")
    .map((character) => characterMap[character] || character)
    .join("");
}

function levenshteinDistance(left, right) {
  const rows = left.length + 1;
  const cols = right.length + 1;
  const matrix = Array.from({ length: rows }, () => Array(cols).fill(0));

  for (let row = 0; row < rows; row += 1) {
    matrix[row][0] = row;
  }

  for (let col = 0; col < cols; col += 1) {
    matrix[0][col] = col;
  }

  for (let row = 1; row < rows; row += 1) {
    for (let col = 1; col < cols; col += 1) {
      const substitutionCost = left[row - 1] === right[col - 1] ? 0 : 1;

      matrix[row][col] = Math.min(
        matrix[row - 1][col] + 1,
        matrix[row][col - 1] + 1,
        matrix[row - 1][col - 1] + substitutionCost,
      );
    }
  }

  return matrix[left.length][right.length];
}

function renderResults(result) {
  resultsSection.classList.remove("hidden");
  resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });

  analyzedUrl.textContent = result.analyzedUrl;
  overallStatus.textContent = result.status;

  scoreCircle.className = `score-circle ${result.severityClass}`;
  scoreCircle.classList.add("hidden");
  statusBadge.className = `result-status-badge ${result.severityClass}`;
  statusBadge.textContent = result.status;

  if (result.score > 0) {
    scoreCard.classList.remove("hidden");
    failedCard.classList.remove("hidden");
    scoreValue.textContent = result.score;
    scoreText.textContent = `${result.score}`;
    renderList(failedList, result.failedChecks, "failed");
    return;
  }

  scoreCard.classList.add("hidden");
  failedCard.classList.add("hidden");
  scoreValue.textContent = "0";
  scoreText.textContent = "";
  failedList.innerHTML = "";
}

function renderList(element, items, type) {
  element.innerHTML = "";

  items.forEach((item) => {
    const listItem = document.createElement("li");
    listItem.classList.add(type);
    listItem.textContent = item;
    element.appendChild(listItem);
  });
}

function showInputError(message) {
  inputFeedback.textContent = message;
  inputFeedback.classList.add("error");
}

function clearInputError() {
  inputFeedback.textContent = "";
  inputFeedback.classList.remove("error");
}

function startLoading() {
  loadingState.classList.remove("hidden");
}

function stopLoading() {
  loadingState.classList.add("hidden");
}
