# 🛡️ ZeroSpoof - Email Security Scanner

A web-based tool to analyze email security configurations (MX, SPF, DKIM, DMARC) for any domain and provide a transparent, versioned score with remediation recommendations.

![ZeroSpoof Scanner](https://img.shields.io/badge/Score_Profile-v1.0-blue) ![Python](https://img.shields.io/badge/Python-3.10+-green) ![Django](https://img.shields.io/badge/Django-6.0-brightgreen)

## ✨ Features

- **MX Validation** (10 pts) - Checks mail exchange records and host resolution
- **SPF Analysis** (25 pts) - Validates syntax, lookup count, and terminal qualifier
- **DKIM Discovery** (25 pts) - Probes common selectors, validates key strength
- **DMARC Evaluation** (40 pts) - Analyzes policy, alignment, and reporting config
- **Provider Detection** - Automatically detects Microsoft 365 & Google Workspace
- **Letter Grades** - A+ to F scoring with color-coded badges
- **Remediation Notes** - Actionable recommendations for each issue

---

## 🚀 Quick Start

### Prerequisites

- Python 3.10 or higher
- pip (Python package manager)
- Git

---

## 📦 Installation

### macOS / Linux

```bash
# Clone the repository
git clone https://github.com/amrit-srivastava/zerospoof.git
cd zerospoof

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run database migrations
python manage.py migrate

# Start the development server
python manage.py runserver 8000
```

### Windows (Command Prompt)

```cmd
:: Clone the repository
git clone https://github.com/amrit-srivastava/zerospoof.git
cd zerospoof

:: Create virtual environment
python -m venv venv

:: Activate virtual environment
venv\Scripts\activate

:: Install dependencies
pip install -r requirements.txt

:: Run database migrations
python manage.py migrate

:: Start the development server
python manage.py runserver 8000
```

### Windows (PowerShell)

```powershell
# Clone the repository
git clone https://github.com/amrit-srivastava/zerospoof.git
cd zerospoof

# Create virtual environment
python -m venv venv

# Activate virtual environment
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Run database migrations
python manage.py migrate

# Start the development server
python manage.py runserver 8000
```

---

## 🌐 Usage

### Web Interface

Open your browser and navigate to:
```
http://127.0.0.1:8000
```

Enter any domain (e.g., `google.com`, `microsoft.com`) and click **Scan**.

### API

```bash
# Check a domain
curl "http://127.0.0.1:8000/api/check?domain=example.com"
```

**Response:**
```json
{
  "domain": "example.com",
  "score": 85,
  "grade": "B",
  "score_version": "1.0",
  "provider": "microsoft365",
  "checks": {
    "mx": { "points": 10, "max_points": 10, ... },
    "spf": { "points": 22, "max_points": 25, ... },
    "dkim": { "points": 21, "max_points": 25, ... },
    "dmarc": { "points": 32, "max_points": 40, ... }
  },
  "remediation": ["..."]
}
```

---

## 📊 Scoring Model (v1.0)

| Control | Max Points | Description |
|---------|------------|-------------|
| MX | 10 | Mail exchange record validation |
| SPF | 25 | Sender Policy Framework checks |
| DKIM | 25 | DomainKeys Identified Mail validation |
| DMARC | 40 | Domain-based Message Authentication |

### Letter Grades

| Grade | Score Range |
|-------|-------------|
| A+ | 95-100 |
| A | 90-94 |
| B | 80-89 |
| C | 70-79 |
| D | 60-69 |
| E | 50-59 |
| F | <50 |

---

## 🏗️ Project Structure

```
zerospoof/
├── manage.py
├── requirements.txt
├── zerospoof/              # Django project settings
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
├── scanner/                # Main application
│   ├── api/               # REST API endpoints
│   ├── checkers/          # MX, SPF, DKIM, DMARC modules
│   ├── services/          # DNS resolver, scoring engine
│   └── constants.py       # Scoring weights & config
└── frontend/              # HTML, CSS, JavaScript
    ├── index.html
    ├── styles.css
    └── app.js
```

---

## 🔧 Configuration

Environment variables (optional):

| Variable | Description | Default |
|----------|-------------|---------|
| `DJANGO_SECRET_KEY` | Django secret key | Auto-generated |
| `DEBUG` | Debug mode | `True` |
| `ALLOWED_HOSTS` | Comma-separated hosts | `*` (debug) |

---

## 🧪 Running Tests

```bash
# Activate virtual environment first
source venv/bin/activate  # macOS/Linux
venv\Scripts\activate     # Windows

# Run tests
pytest scanner/tests/ -v
```

---

## 📝 License

MIT License - see [LICENSE](LICENSE) for details.

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📧 Contact

Built by [Dunetrails](https://www.dunetrails.com)
