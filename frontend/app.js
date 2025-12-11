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
 * Generate PDF report client-side using jsPDF
 * Uses only ASCII-safe characters to avoid font encoding issues
 */
function generatePDF() {
    if (!currentScanResult) {
        alert('No scan results to download. Please scan a domain first.');
        return;
    }

    var jsPDF = window.jspdf.jsPDF;
    var doc = new jsPDF();
    var result = currentScanResult;

    // Colors (RGB arrays)
    var primaryColor = [99, 102, 241];
    var successColor = [16, 185, 129];
    var warningColor = [245, 158, 11];
    var errorColor = [239, 68, 68];
    var textColor = [51, 51, 51];
    var mutedColor = [128, 128, 128];

    var yPos = 20;
    var leftMargin = 20;
    var pageWidth = doc.internal.pageSize.getWidth();

    // Header
    doc.setFontSize(24);
    doc.setTextColor(primaryColor[0], primaryColor[1], primaryColor[2]);
    doc.text('ZeroSpoof', leftMargin, yPos);

    doc.setFontSize(12);
    doc.setTextColor(mutedColor[0], mutedColor[1], mutedColor[2]);
    doc.text('Email Security Report', leftMargin + 55, yPos);

    yPos += 15;

    // Domain and date
    doc.setFontSize(16);
    doc.setTextColor(textColor[0], textColor[1], textColor[2]);
    doc.text('Domain: ' + result.domain, leftMargin, yPos);

    yPos += 8;
    doc.setFontSize(10);
    doc.setTextColor(mutedColor[0], mutedColor[1], mutedColor[2]);
    doc.text('Generated: ' + new Date().toLocaleString(), leftMargin, yPos);
    doc.text('Score Profile v' + result.score_version, leftMargin + 80, yPos);

    yPos += 15;

    // Score and Grade box
    doc.setFillColor(240, 240, 245);
    doc.roundedRect(leftMargin, yPos, pageWidth - 40, 25, 3, 3, 'F');

    doc.setFontSize(24);
    doc.setTextColor(primaryColor[0], primaryColor[1], primaryColor[2]);
    doc.text(result.score + '/100', leftMargin + 10, yPos + 17);

    doc.setFontSize(28);
    var gradeColor = successColor;
    if (result.grade === 'B') {
        gradeColor = [41, 121, 255];
    } else if (result.grade === 'C') {
        gradeColor = warningColor;
    } else if (result.grade === 'D' || result.grade === 'E' || result.grade === 'F') {
        gradeColor = errorColor;
    }
    doc.setTextColor(gradeColor[0], gradeColor[1], gradeColor[2]);
    doc.text(result.grade, leftMargin + 70, yPos + 18);

    doc.setFontSize(11);
    doc.setTextColor(mutedColor[0], mutedColor[1], mutedColor[2]);
    doc.text('Provider: ' + formatProvider(result.provider), leftMargin + 100, yPos + 17);

    yPos += 35;

    // Horizontal line
    doc.setDrawColor(200, 200, 200);
    doc.line(leftMargin, yPos, pageWidth - leftMargin, yPos);
    yPos += 10;

    // Controls section
    var controls = [
        { name: 'MX Records', key: 'mx' },
        { name: 'SPF (Sender Policy Framework)', key: 'spf' },
        { name: 'DKIM (DomainKeys Identified Mail)', key: 'dkim' },
        { name: 'DMARC (Domain-based Message Authentication)', key: 'dmarc' }
    ];

    for (var i = 0; i < controls.length; i++) {
        var control = controls[i];
        var check = result.checks[control.key];

        // Check if we need a new page
        if (yPos > 250) {
            doc.addPage();
            yPos = 20;
        }

        // Control header
        doc.setFontSize(13);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(primaryColor[0], primaryColor[1], primaryColor[2]);
        doc.text(control.name, leftMargin, yPos);

        // Score
        var scorePercentage = (check.points / check.max_points) * 100;
        var scoreColor = scorePercentage >= 80 ? successColor :
            scorePercentage >= 50 ? warningColor : errorColor;
        doc.setTextColor(scoreColor[0], scoreColor[1], scoreColor[2]);
        doc.text(check.points + '/' + check.max_points, pageWidth - 40, yPos);

        yPos += 8;
        doc.setFont('helvetica', 'normal');

        // Messages
        if (check.messages && check.messages.length > 0) {
            for (var j = 0; j < check.messages.length; j++) {
                var msg = check.messages[j];

                if (yPos > 275) {
                    doc.addPage();
                    yPos = 20;
                }

                doc.setFontSize(9);
                var msgColor = mutedColor;
                var icon = '[i]';

                if (msg.level === 'success') {
                    msgColor = successColor;
                    icon = '[OK]';
                } else if (msg.level === 'warning') {
                    msgColor = warningColor;
                    icon = '[!]';
                } else if (msg.level === 'error') {
                    msgColor = errorColor;
                    icon = '[X]';
                }

                doc.setTextColor(msgColor[0], msgColor[1], msgColor[2]);

                var text = icon + ' ' + msg.text;
                var lines = doc.splitTextToSize(text, pageWidth - 50);
                doc.text(lines, leftMargin + 5, yPos);
                yPos += lines.length * 4.5;
            }
        }

        yPos += 10;
    }

    // Remediation section
    if (result.remediation && result.remediation.length > 0) {
        if (yPos > 220) {
            doc.addPage();
            yPos = 20;
        }

        // Horizontal line
        doc.setDrawColor(200, 200, 200);
        doc.line(leftMargin, yPos, pageWidth - leftMargin, yPos);
        yPos += 10;

        doc.setFontSize(13);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(warningColor[0], warningColor[1], warningColor[2]);
        doc.text('Recommended Actions', leftMargin, yPos);
        yPos += 10;
        doc.setFont('helvetica', 'normal');

        // Remove duplicates
        var uniqueRemediation = [];
        for (var k = 0; k < result.remediation.length; k++) {
            if (uniqueRemediation.indexOf(result.remediation[k]) === -1) {
                uniqueRemediation.push(result.remediation[k]);
            }
        }

        for (var m = 0; m < uniqueRemediation.length; m++) {
            if (yPos > 275) {
                doc.addPage();
                yPos = 20;
            }

            doc.setFontSize(9);
            doc.setTextColor(textColor[0], textColor[1], textColor[2]);
            var remText = (m + 1) + '. ' + uniqueRemediation[m];
            var remLines = doc.splitTextToSize(remText, pageWidth - 50);
            doc.text(remLines, leftMargin + 5, yPos);
            yPos += remLines.length * 4.5 + 3;
        }
    }

    // Footer on all pages
    var pageCount = doc.internal.getNumberOfPages();
    for (var p = 1; p <= pageCount; p++) {
        doc.setPage(p);
        doc.setFontSize(8);
        doc.setTextColor(mutedColor[0], mutedColor[1], mutedColor[2]);
        doc.text(
            'ZeroSpoof by Dunetrails | Page ' + p + ' of ' + pageCount,
            pageWidth / 2,
            doc.internal.pageSize.getHeight() - 10,
            { align: 'center' }
        );
    }

    // Save the PDF
    doc.save('zerospoof-' + result.domain + '-report.pdf');
}

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', init);

