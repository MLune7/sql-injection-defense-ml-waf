# SQL Injection Defense — ML-Powered WAF

A full-stack web application that detects and blocks SQL injection attacks in real time using a multi-layer Web Application Firewall (WAF) powered by Machine Learning.

Built as a Bachelor's thesis project in Computer Science.

---

## Features

- **4-Layer WAF Detection Engine:**
  - Blacklist — known attack pattern database
  - Regex — 36 handcrafted SQL injection patterns
  - Machine Learning — Random Forest classifier (99.75% accuracy)
  - Encoding Detection — URL, Unicode, Hex, CHAR(), double-encoding, comment obfuscation
- **React Frontend** — Login, Register, Product Search, WAF Scanner, Admin Panel, Dashboard
- **Flask Backend** — REST API with SQLite database
- **JWT Authentication** — Access tokens (15 min) + Refresh tokens (7 days) via HTTP-only cookies
- **Rate Limiting** — 100 requests/min per IP
- **IP Blocking** — Auto-block after 3 detected attacks (1 hour)
- **Password Hashing** — PBKDF2-SHA256
- **Security Headers** — X-Frame-Options, X-XSS-Protection, Content-Security-Policy
- **XSS Detection** — Blocks `<script>`, `javascript:`, `onclick=` patterns

---

## Tech Stack

**Frontend:** React, Axios, JavaScript (ES6+), CSS3  
**Backend:** Flask, SQLite, Flask-JWT-Extended, Werkzeug  
**Machine Learning:** scikit-learn, NumPy, Pandas, Joblib, XGBoost, TensorFlow  
**Security:** Custom WAF Engine, JWT, PBKDF2, Rate Limiting  

---

## ML Model Performance

| Model | Accuracy |
|---|---|
| **Random Forest** | **99.75%** |
| SVM | 98.10% |
| Logistic Regression | 97.20% |
| Naive Bayes | 94.30% |

Trained on **33,420 samples** (Kaggle SQLi dataset + OWASP attack examples).  
Cross-validation: 99.70% ± 0.12% (5-Fold)

---

## Project Structure

```
sql-injection-defense-ml-waf/
├── backend/
│   ├── app.py                  # Main Flask application & API routes
│   ├── waf.py                  # WAF engine (4-layer detection)
│   ├── security_middleware.py  # Rate limiting, IP blocking
│   ├── jwt_auth.py             # JWT authentication logic
│   ├── database.py             # Database setup & queries
│   ├── security_logger.py      # Attack logging
│   ├── ml/
│   │   ├── ml_detector.py      # ML inference logic
│   │   └── train_model.py      # Model training script
│   └── data/
│       ├── random_forest_model.pkl
│       ├── Modified_SQL_Dataset.csv
│       └── sqli_payloads_expanded.txt
├── frontend/
│   └── src/
│       ├── App.js
│       ├── components/         # Login, Register, Dashboard, Scanner, etc.
│       └── services/api.js
└── README.md
```

---

## Getting Started

### Prerequisites
- Python 3.8+
- Node.js 14+

### Backend Setup

```bash
cd backend
pip install -r requirements.txt
python app.py
```

The API will run at `http://localhost:5000`.

### Frontend Setup

```bash
cd frontend
npm install
npm start
```

The app will open at `http://localhost:3000`.

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/login` | User login |
| POST | `/api/register` | User registration |
| GET | `/api/products` | List products |
| POST | `/api/search` | Search products |
| POST | `/api/scan` | Test WAF scanner |
| GET | `/api/admin/users` | List users (admin only) |

---

## How It Works

1. A request comes in from the frontend
2. Security middleware checks IP block list and rate limit
3. WAF engine runs all 4 detection layers in sequence
4. If any layer flags the input → **403 Forbidden**, attack logged
5. Clean requests pass through to the Flask routes and database

---

## License

MIT
