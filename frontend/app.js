/**
 * ZeroSpoof - Email Security Scanner
 * Frontend JavaScript Application
 */

// DOM Elements
const scanForm = document.getElementById('scanForm');
const domainInput = document.getElementById('domainInput');
const scanButton = document.getElementById('scanButton');
const buttonText = scanButton.querySelector('.button-text');
const buttonLoader = scanButton.querySelector('.button-loader');
const errorMessage = document.getElementById('errorMessage');
const resultsSection = document.getElementById('resultsSection');
const downloadPdfBtn = document.getElementById('downloadPdfBtn');

// API endpoint
const API_URL = '/api/check';

// Store current scan result for PDF generation
let currentScanResult = null;

// Message icons
const MESSAGE_ICONS = {
    success: '✓',
    warning: '⚠',
    error: '✗',
    info: 'ℹ'
};

// Grade colors
const GRADE_COLORS = {
    'A+': '#00c853',
    'A': '#00e676',
    'B': '#2979ff',
    'C': '#ffea00',
    'D': '#ff9100',
    'E': '#ff6d00',
    'F': '#ff1744'
};

/**
 * Initialize the application
 */
function init() {
    scanForm.addEventListener('submit', handleScan);
    downloadPdfBtn.addEventListener('click', generatePDF);
    domainInput.focus();
}

/**
 * Handle form submission
 */
async function handleScan(e) {
    e.preventDefault();

    const domain = domainInput.value.trim();

    if (!domain) {
        showError('Please enter a domain name');
        return;
    }

    // Clean domain input
    const cleanedDomain = cleanDomain(domain);

    if (!isValidDomain(cleanedDomain)) {
        showError('Please enter a valid domain name (e.g., example.com)');
        return;
    }

    hideError();
    setLoading(true);

    try {
        const result = await scanDomain(cleanedDomain);
        currentScanResult = result; // Store for PDF generation
        displayResults(result);
    } catch (error) {
        showError(error.message || 'Failed to scan domain. Please try again.');
    } finally {
        setLoading(false);
    }
}

/**
 * Clean domain input
 */
function cleanDomain(domain) {
    domain = domain.toLowerCase().trim();

    // Remove protocol
    if (domain.startsWith('http://')) {
        domain = domain.slice(7);
    }
    if (domain.startsWith('https://')) {
        domain = domain.slice(8);
    }

    // Remove path and port
    domain = domain.split('/')[0];
    domain = domain.split(':')[0];

    return domain;
}

/**
 * Validate domain format
 */
function isValidDomain(domain) {
    const pattern = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/;
    return pattern.test(domain);
}

/**
 * Scan a domain via API
 */
async function scanDomain(domain) {
    const response = await fetch(`${API_URL}?domain=${encodeURIComponent(domain)}`);
    const data = await response.json();

    if (!response.ok) {
        throw new Error(data.error || 'Scan failed');
    }

    return data;
}

/**
 * Display scan results
 */
function displayResults(result) {
    // Update score circle
    const scoreCircle = document.getElementById('scoreCircle');
    const scoreValue = document.getElementById('scoreValue');
    const gradeBadge = document.getElementById('gradeBadge');

    scoreValue.textContent = result.score;
    gradeBadge.textContent = result.grade;
    gradeBadge.style.color = result.grade_color || GRADE_COLORS[result.grade];
    gradeBadge.style.background = `${result.grade_color || GRADE_COLORS[result.grade]}20`;

    // Update score circle border color based on grade
    scoreCircle.style.borderColor = result.grade_color || GRADE_COLORS[result.grade];

    // Update domain and provider info
    document.getElementById('domainName').textContent = result.domain;
    document.getElementById('providerInfo').textContent =
        `Provider: ${formatProvider(result.provider)}`;
    document.getElementById('versionInfo').textContent =
        `Score Profile v${result.score_version}`;
    document.getElementById('scoreVersion').textContent = result.score_version;

    // Update control cards
    updateControlCard('mx', result.checks.mx);
    updateControlCard('spf', result.checks.spf);
    updateControlCard('dkim', result.checks.dkim);
    updateControlCard('dmarc', result.checks.dmarc);

    // Update remediation section
    updateRemediation(result.remediation);

    // Show results
    resultsSection.hidden = false;

    // Scroll to results
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

/**
 * Update a control card with check results
 */
function updateControlCard(controlName, checkResult) {
    const scoreElement = document.getElementById(`${controlName}Score`);
    const messagesElement = document.getElementById(`${controlName}Messages`);

    // Update score
    scoreElement.textContent = `${checkResult.points}/${checkResult.max_points}`;

    // Update score color based on percentage
    const percentage = (checkResult.points / checkResult.max_points) * 100;
    if (percentage >= 80) {
        scoreElement.style.color = '#10b981';
    } else if (percentage >= 50) {
        scoreElement.style.color = '#f59e0b';
    } else {
        scoreElement.style.color = '#ef4444';
    }

    // Update messages
    messagesElement.innerHTML = '';

    if (checkResult.messages && checkResult.messages.length > 0) {
        checkResult.messages.forEach(msg => {
            const messageEl = createMessageElement(msg.level, msg.text);
            messagesElement.appendChild(messageEl);
        });
    } else {
        messagesElement.innerHTML = '<p class="message info">No details available</p>';
    }
}

/**
 * Create a message element
 */
function createMessageElement(level, text) {
    const div = document.createElement('div');
    div.className = `message ${level}`;

    const icon = document.createElement('span');
    icon.className = 'message-icon';
    icon.textContent = MESSAGE_ICONS[level] || 'ℹ';

    const textSpan = document.createElement('span');
    textSpan.textContent = text;

    div.appendChild(icon);
    div.appendChild(textSpan);

    return div;
}

/**
 * Update remediation section
 */
function updateRemediation(remediation) {
    const section = document.getElementById('remediationSection');
    const list = document.getElementById('remediationList');

    if (!remediation || remediation.length === 0) {
        section.hidden = true;
        return;
    }

    list.innerHTML = '';

    // Remove duplicates
    const uniqueRemediation = [...new Set(remediation)];

    uniqueRemediation.forEach(item => {
        const li = document.createElement('li');
        li.textContent = item;
        list.appendChild(li);
    });

    section.hidden = false;
}

/**
 * Format provider name for display
 */
function formatProvider(provider) {
    const providers = {
        'microsoft365': 'Microsoft 365',
        'google_workspace': 'Google Workspace',
        'unknown': 'Unknown'
    };
    return providers[provider] || provider;
}

/**
 * Show error message
 */
function showError(message) {
    errorMessage.textContent = message;
    errorMessage.hidden = false;
}

/**
 * Hide error message
 */
function hideError() {
    errorMessage.hidden = true;
}

/**
 * Set loading state
 */
function setLoading(loading) {
    scanButton.disabled = loading;
    buttonText.hidden = loading;
    buttonLoader.hidden = !loading;
    domainInput.disabled = loading;
}

/**
 * Download PDF report from server
 */
function generatePDF() {
    if (!currentScanResult) {
        alert('No scan results to download. Please scan a domain first.');
        return;
    }

    const domain = currentScanResult.domain;

    // Direct navigation - browser handles download based on Content-Disposition header
    window.location.href = `/api/download-pdf?domain=${encodeURIComponent(domain)}`;
}

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', init);
