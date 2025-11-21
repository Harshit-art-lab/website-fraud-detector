
# 🌐 Website Fraud Detector

A FastAPI-based tool that analyzes a website URL and checks if it may be fraudulent or unsafe.
It returns a **risk score**, **risk level**, and a list of detected issues.

---

## 📦 Installation

Create and activate a virtual environment:

```bash
python -m venv venv
source venv/bin/activate      # macOS / Linux
# venv\Scripts\activate       # Windows
```

Install dependencies:

```bash
pip install -r requirements.txt
```

If `requirements.txt` is missing:

```bash
pip install fastapi uvicorn requests python-whois dnspython beautifulsoup4 tldextract
```

---

## 🚀 Run the Server

Start the FastAPI app:

```bash
uvicorn app:app --reload
```

API documentation:

* 📘 Swagger UI → [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
* 📙 ReDoc → [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

---

## 🧪 API Usage

### Endpoint

```
POST /analyze
```

### Request

```json
{
  "url": "https://example.com/login"
}
```

### Example Response

```json
{
  "success": true,
  "url": "https://example.com/login",
  "risk_score": 42,
  "risk_level": "medium_risk",
  "is_legitimate": false,
  "issues": [
    {
      "type": "phishing_keywords",
      "details": "Found keyword: login"
    }
  ],
  "issue_count": 1
}
```

---

## 📁 Project Structure

```
website-fraud-detector/
├── app.py                # FastAPI server
├── fraud_detector.py     # URL analysis logic
├── requirements.txt
└── README.md
```

---

