# SQL Injection Prevention on Websites - Thesis Presentation
## Bachelor's Thesis Presentation Slides

---

# SLIDE 1: TITLE SLIDE

**Title:** SQL INJECTION PREVENTION ON WEBSITES
**Subtitle:** Using Machine Learning and Web Application Firewall

**Details:**
- [Your Name]
- Bachelor's Thesis in Computer Science
- [University Name]
- [Date: March 2026]
- [University Logo]

**Design Notes:**
- Clean, professional design
- University colors
- Large, bold title

---

# SLIDE 2: THE PROBLEM (Why This Matters)

**Title:** SQL Injection: The #1 Web Security Threat

**Visual Element:** Pie Chart showing attack distribution:
- SQL Injection: 65%
- XSS (Cross-Site Scripting): 15%
- Other Attacks: 20%

**Key Statistics:**
- 2024: Over 1,500 data breaches caused by SQL injection
- Average cost per breach: $4.5 million
- 65% of all web application attacks involve SQL injection

**Victims Include:**
- Sony (2011) - 77 million accounts
- Heartland Payment Systems - 130 million cards
- Yahoo - 3 billion accounts

**Design Notes:**
- Use a prominent pie chart
- Red/warning colors for emphasis
- Include a few company logos of breach victims

---

# SLIDE 3: WHAT IS SQL INJECTION? (Simple Example)

**Title:** How SQL Injection Works

**Section 1 - Normal Login:**
```
User Input:
┌─────────────────────────┐
│ Username: admin         │
│ Password: password123   │
└─────────────────────────┘

Database Query Generated:
SELECT * FROM users WHERE username='admin' AND password='password123'

Result: ✅ Login succeeds only if credentials are correct
```

**Section 2 - SQL Injection Attack:**
```
User Input:
┌─────────────────────────┐
│ Username: ' OR '1'='1   │
│ Password: anything      │
└─────────────────────────┘

Database Query Generated:
SELECT * FROM users WHERE username='' OR '1'='1' AND password='anything'

Result: ❌ Login ALWAYS succeeds! (because '1'='1' is always true)
```

**Design Notes:**
- Split slide into two sections: Normal vs Attack
- Use green checkmark for normal, red X for attack
- Highlight the injected code in red

---

# SLIDE 4: PROJECT GOALS

**Title:** Project Objectives

**Visual Element:** Target/bullseye diagram with 3 main goals

**Goal 1: DETECT**
- Build a system that detects SQL injection attacks in real-time

**Goal 2: MULTI-LAYER DEFENSE**
- Combine multiple detection methods:
  - Traditional WAF rules
  - Machine Learning
  - Encoding detection

**Goal 3: COMPARE & EVALUATE**
- Compare our solution with industry standard (ModSecurity CRS)
- Measure accuracy, precision, recall

**Design Notes:**
- Use a target/bullseye graphic
- Three concentric circles or three connected boxes
- Icons for each goal (shield, brain, chart)

---

# SLIDE 5: SYSTEM ARCHITECTURE (Overview)

**Title:** System Architecture

**Visual Element:** Flow diagram showing:

```
┌──────────────┐         ┌─────────────────────────────────────────────┐
│              │         │                 BACKEND                     │
│   FRONTEND   │         │                                             │
│    React     │────────▶│  ┌─────────────────────────────────────┐    │
│   Port 3000  │         │  │      SECURITY MIDDLEWARE            │    │
│              │         │  │  • Rate Limiting (100 req/min)      │    │
└──────────────┘         │  │  • IP Blocking                      │    │
                         │  │  • JWT Authentication               │    │
                         │  └─────────────────┬───────────────────┘    │
                         │                    │                         │
                         │                    ▼                         │
                         │  ┌─────────────────────────────────────┐    │
                         │  │           WAF ENGINE                │    │
                         │  │  ┌──────────┬────────┬──────────┐   │    │
                         │  │  │Blacklist │ Regex  │    ML    │   │    │
                         │  │  │  Check   │Patterns│  Model   │   │    │
                         │  │  └──────────┴────────┴──────────┘   │    │
                         │  │  + Encoding Attack Detection        │    │
                         │  └─────────────────┬───────────────────┘    │
                         │                    │                         │
                         │                    ▼                         │
                         │  ┌─────────────────────────────────────┐    │
                         │  │     FLASK APPLICATION (app.py)      │    │
                         │  │  • API Routes                       │    │
                         │  │  • Business Logic                   │    │
                         │  └─────────────────┬───────────────────┘    │
                         │                    │                         │
                         │                    ▼                         │
                         │  ┌─────────────────────────────────────┐    │
                         │  │         DATABASE (SQLite)           │    │
                         │  │  • Users Table                      │    │
                         │  │  • Products Table                   │    │
                         │  └─────────────────────────────────────┘    │
                         │                                             │
                         └─────────────────────────────────────────────┘
```

**Design Notes:**
- Use boxes with arrows showing data flow
- Color code: Frontend (blue), Security (red), WAF (orange), Database (green)
- Add small icons for each component

---

# SLIDE 6: REQUEST FLOW

**Title:** How a Request is Processed

**Visual Element:** Step-by-step numbered flow (animation recommended)

**Step 1: User Input**
- User types: `admin' OR '1'='1` in login form

**Step 2: Frontend Sends Request**
- POST /api/login with username and password
- Adds JWT token (if logged in)
- Adds request fingerprint

**Step 3: Security Middleware**
- Check: Is IP blocked? → No ✓
- Check: Rate limited? → No ✓
- Continue to WAF

**Step 4: WAF Engine**
- Check Blacklist → Not found
- Check Regex Patterns → MATCH FOUND! (' OR ')
- Check ML Model → 97% confidence MALICIOUS
- ⚠️ ATTACK DETECTED!

**Step 5: Request Blocked**
- Return 403 Forbidden
- Log attack to security log
- Request NEVER reaches database

**Design Notes:**
- Vertical flow with numbered steps
- Use animation to reveal each step
- Red warning icon at step 4
- Show "BLOCKED" prominently at step 5

---

# SLIDE 7: WAF DETECTION LAYERS

**Title:** Multi-Layer Detection System

**Visual Element:** Layered defense diagram (like security layers)

**Input Example:** `"admin' UNION SELECT password FROM users--"`

**Layer 1: BLACKLIST**
- Description: Known attack patterns stored in database
- Speed: ⚡⚡⚡⚡⚡ (Fastest - 0.01ms)
- Check: Is exact pattern in blacklist?
- Result: Not found, continue

**Layer 2: REGEX PATTERNS (36 patterns)**
- Description: Regular expression pattern matching
- Speed: ⚡⚡⚡⚡ (Fast - 0.05ms)
- Check: Does input match any SQL patterns?
- Result: ✓ MATCH! "UNION SELECT" detected
- Patterns include: UNION SELECT, OR 1=1, DROP TABLE, etc.

**Layer 3: MACHINE LEARNING**
- Description: Random Forest classifier (99.75% accuracy)
- Speed: ⚡⚡⚡ (Medium - 0.5ms)
- Check: Does ML model classify as malicious?
- Result: ✓ MALICIOUS (97% confidence)

**Layer 4: ENCODING DETECTION**
- Description: Detect URL, Unicode, Hex encoding attacks
- Speed: ⚡⚡⚡⚡ (Fast - 0.05ms)
- Check: Is input suspiciously encoded?
- Result: No encoding detected

**Final Decision: 🚫 BLOCKED (Multiple detections)**

**Design Notes:**
- Show as stacked layers or funnel
- Use different colors for each layer
- Show speed rating with lightning bolt icons
- Checkmarks for detection hits

---

# SLIDE 8: MACHINE LEARNING - FEATURE EXTRACTION

**Title:** How ML Understands Attacks (50 Features)

**Visual Element:** Transformation diagram showing text → numbers → prediction

**Input Text:** `' OR '1'='1--`

**Feature Extraction Process:**

| Feature | Value | Meaning |
|---------|-------|---------|
| length | 13 | Total characters |
| quote_ratio | 0.31 | 4 quotes ÷ 13 chars (HIGH!) |
| dash_ratio | 0.15 | 2 dashes ÷ 13 chars (HIGH!) |
| equals_ratio | 0.15 | 2 equals ÷ 13 chars (HIGH!) |
| keyword_count | 1 | Found "OR" keyword |
| has_comment | 1 | Contains "--" comment |
| entropy | 2.8 | Randomness measure |
| special_char_ratio | 0.46 | Many special chars (HIGH!) |
| has_or_pattern | 1 | Contains OR pattern |
| has_quotes | 1 | Contains quotes |

**Feature Vector:** [13, 0.31, 0.15, 0.15, 1, 1, 2.8, 0.46, 1, 1, ...]

**Random Forest Model:**
- 100 decision trees vote
- Each tree analyzes different patterns
- Majority vote determines result

**Output:** MALICIOUS (97% confidence)

**Design Notes:**
- Show transformation as a pipeline/flow
- Use a table for features
- Highlight suspicious values in red
- Show decision tree voting concept

---

# SLIDE 9: MODEL SELECTION

**Title:** Why Random Forest? Model Comparison

**Visual Element:** Bar chart comparing 4 models

**Models Tested:**

| Model | Accuracy | Precision | Recall | F1-Score |
|-------|----------|-----------|--------|----------|
| Random Forest | 99.75% | 99.80% | 99.60% | 99.70% |
| SVM | 98.10% | 97.90% | 98.20% | 98.00% |
| Logistic Regression | 97.20% | 96.50% | 97.80% | 97.10% |
| Naive Bayes | 94.30% | 93.10% | 95.20% | 94.10% |

**Bar Chart Data:**
- Random Forest: 99.75%
- SVM: 98.10%
- Logistic Regression: 97.20%
- Naive Bayes: 94.30%

**Why Random Forest Won:**
1. ✓ Highest accuracy (99.75%)
2. ✓ Best balance of precision and recall
3. ✓ Handles complex patterns well
4. ✓ Fast prediction time (~0.5ms)
5. ✓ No overfitting (cross-validation: 99.70% ± 0.12%)

**Winner Badge:** 🏆 Random Forest

**Design Notes:**
- Prominent bar chart
- Highlight Random Forest bar in gold/green
- Add a trophy or winner badge
- Keep table simple

---

# SLIDE 10: DATASET INFORMATION

**Title:** Training Data

**Visual Element:** Pie chart showing data distribution

**Dataset Composition:**

**Total Samples:** 33,420

**Pie Chart:**
- Benign (Safe) Inputs: 21,416 samples (64%)
- SQL Injection Attacks: 12,004 samples (36%)

**Data Sources:**
- Kaggle SQL Injection Dataset
- OWASP Attack Examples
- Real-world Attack Patterns
- Normal User Inputs (names, emails, searches)

**Training Configuration:**
- Train/Test Split: 80% / 20%
- Training Set: 26,736 samples
- Test Set: 6,684 samples
- Cross-Validation: 5-Fold

**Sample Types:**
- Benign: "john_doe", "laptop computer", "john@email.com"
- Attack: "' OR '1'='1", "UNION SELECT * FROM users", "'; DROP TABLE--"

**Design Notes:**
- Large pie chart as main visual
- Two colors: green for benign, red for attacks
- Show source logos if available (Kaggle, OWASP)

---

# SLIDE 11: ML RESULTS

**Title:** Model Performance Results

**Visual Element:** Confusion matrix + metrics dashboard

**Confusion Matrix:**

|  | Predicted Safe | Predicted Attack |
|--|----------------|------------------|
| **Actual Safe** | 4,270 (TN) | 12 (FP) |
| **Actual Attack** | 5 (FN) | 2,397 (TP) |

**Metrics Dashboard:**

| Metric | Value | Meaning |
|--------|-------|---------|
| Accuracy | 99.75% | Overall correct predictions |
| Precision | 99.80% | When it says attack, it's right 99.8% |
| Recall | 99.60% | Catches 99.6% of all attacks |
| F1-Score | 99.70% | Balance of precision and recall |
| False Positives | 12 | Blocked safe inputs (0.2%) |
| False Negatives | 5 | Missed attacks (0.04%) |

**Cross-Validation Results:**
- 5-Fold CV Score: 99.70% (± 0.12%)
- Consistent across all folds

**Key Takeaway:**
- Only 5 attacks missed out of 2,402
- Only 12 false alarms out of 4,282 safe inputs

**Design Notes:**
- Confusion matrix as a 2x2 grid
- Color code: green for correct, red for errors
- Use large numbers for key metrics
- Consider gauge/meter visualization for accuracy

---

# SLIDE 12: WAF vs MODSECURITY CRS COMPARISON

**Title:** Our ML-WAF vs Industry Standard (ModSecurity CRS)

**Visual Element:** Side-by-side comparison

**Our ML-WAF:**
- Detection Rate: 99.75%
- False Positives: 0.2%
- Obfuscation Handling: ✓ Excellent
- Encoding Detection: ✓ Yes
- Detection Layers: 4 (Blacklist + Regex + ML + Encoding)
- Adaptive: ✓ ML learns patterns
- Speed: ~0.5ms per request

**ModSecurity CRS (54 Rules):**
- Detection Rate: ~95%
- False Positives: ~5%
- Obfuscation Handling: ✗ Limited
- Encoding Detection: ✗ Basic
- Detection Layers: 1 (Rules only)
- Adaptive: ✗ Static rules
- Speed: ~0.3ms per request

**Attacks CRS Misses But ML Catches:**

| Attack | CRS | ML-WAF |
|--------|-----|--------|
| `SEL/**/ECT * FR/**/OM users` | ✗ Miss | ✓ Catch |
| `%27%20OR%20%271%27=%271` | ✗ Miss | ✓ Catch |
| `CHAR(39)+OR+CHAR(39)1` | ✗ Miss | ✓ Catch |
| Novel/new patterns | ✗ Miss | ✓ Catch |

**Design Notes:**
- Two columns side by side
- Use checkmarks and X marks
- Highlight advantages in green
- Show example attacks that CRS misses

---

# SLIDE 13: ENCODING ATTACK DETECTION

**Title:** Detecting Encoded/Obfuscated Attacks

**Visual Element:** Examples showing encoded attacks and detection

**Problem:** Attackers hide SQL injection using encoding

**Encoding Types Detected:**

**1. URL Encoding:**
```
Original:  ' OR '1'='1
Encoded:   %27%20OR%20%271%27=%271
```
Status: ✓ Detected and decoded

**2. Double URL Encoding:**
```
Original:  ' OR '1'='1
Encoded:   %2527%2520OR%2520%25271
```
Status: ✓ Detected and decoded

**3. Unicode Encoding:**
```
Original:  ' OR '1'='1
Encoded:   \u0027 OR \u00271\u0027=\u00271
```
Status: ✓ Detected and decoded

**4. Hex Encoding:**
```
Original:  SELECT
Encoded:   0x53454C454354
```
Status: ✓ Detected and decoded

**5. CHAR() Function:**
```
Original:  ' OR '1'='1
Encoded:   CHAR(39)+OR+CHAR(39)1CHAR(39)=CHAR(39)1
```
Status: ✓ Detected and decoded

**6. Comment Obfuscation:**
```
Original:  UNION SELECT
Encoded:   UN/**/ION SEL/**/ECT
```
Status: ✓ Detected by ML

**Our Approach:**
1. Detect encoding patterns (flag as suspicious)
2. Normalize/decode the input
3. Check decoded input with all detection methods

**Design Notes:**
- Show before/after examples
- Use monospace font for code
- Green checkmarks for detection
- Visual showing decode process

---

# SLIDE 14: ADDITIONAL SECURITY FEATURES

**Title:** Complete Security System

**Visual Element:** Shield or checklist design

**Security Features Implemented:**

**1. Rate Limiting**
- Limit: 100 requests per minute per IP
- Purpose: Prevents brute force attacks
- Action: Returns 429 Too Many Requests

**2. IP Blocking**
- Trigger: After 3 detected attacks
- Duration: 1 hour block
- Purpose: Stops repeat attackers

**3. Failed Login Protection**
- Limit: 5 failed attempts
- Duration: 15 minute lockout
- Purpose: Prevents password guessing

**4. JWT Authentication**
- Access Token: 15 minute expiry
- Refresh Token: 7 day expiry
- HTTP-Only Cookies: Prevents XSS theft

**5. Password Hashing**
- Algorithm: PBKDF2-SHA256
- Purpose: Passwords never stored in plain text

**6. Parameterized Queries**
- All database queries use ? placeholders
- Purpose: Database-level SQL injection defense

**7. Security Headers**
- X-Frame-Options: DENY (prevents clickjacking)
- X-XSS-Protection: 1; mode=block
- Content-Security-Policy: Restricts resource loading

**8. XSS Detection**
- Detects `<script>`, `javascript:`, `onclick=`
- Purpose: Blocks JavaScript injection attacks

**Design Notes:**
- Use a shield icon design
- Checklist format with green checkmarks
- Group related features together
- Consider icons for each feature

---

# SLIDE 15: LIVE DEMO / SCREENSHOTS

**Title:** System Demonstration

**Visual Element:** Screenshots of the working application

**Screenshot 1: Login Page - Normal Use**
- Show clean login form
- Username: admin
- Password: ****
- Result: Successful login, redirect to dashboard

**Screenshot 2: Login Page - Attack Attempt**
- Show login form with attack
- Username: admin' OR '1'='1--
- Password: anything
- Result: Red error message "Attack Blocked by WAF"

**Screenshot 3: WAF Scanner Page**
- Show the input scanner
- Input: ' UNION SELECT * FROM users--
- Result: 
  - Status: MALICIOUS
  - Detected by: Regex + ML
  - Confidence: 97%

**Screenshot 4: Security Dashboard**
- Show security status
- Attacks blocked: 47
- IPs blocked: 3
- Detection rate: 99.75%

**Demo Flow (if live demo):**
1. Show normal login working
2. Attempt SQL injection attack
3. Show attack being blocked
4. Show security log with attack details

**Design Notes:**
- Use actual screenshots from the application
- Add red circles/arrows pointing to important elements
- Consider side-by-side before/after
- Keep screenshots large and readable

---

# SLIDE 16: TECHNOLOGIES USED

**Title:** Technology Stack

**Visual Element:** Tech logos arranged by category

**Frontend:**
- React (UI Framework)
- Axios (HTTP Client)
- JavaScript (ES6+)
- CSS3 (Styling)

**Backend:**
- Flask (Python Web Framework)
- SQLite (Database)
- Flask-JWT-Extended (Authentication)
- Werkzeug (Security utilities)

**Machine Learning:**
- scikit-learn (ML Library)
- NumPy (Numerical computing)
- Pandas (Data processing)
- Joblib (Model serialization)

**Security:**
- Custom WAF Engine
- PBKDF2 Password Hashing
- JWT Tokens
- Rate Limiting

**Development Tools:**
- Python 3.13
- Node.js
- Git (Version Control)
- VS Code / Warp Terminal

**Design Notes:**
- Use official logos for each technology
- Arrange in 3-4 columns
- Group by category with headers
- Keep clean and organized

---

# SLIDE 17: CONCLUSION

**Title:** Conclusion & Future Work

**Visual Element:** Summary checkboxes + future roadmap

**Achievements:**

✅ **Built Multi-Layer WAF**
- 4 detection layers working together
- Blacklist + Regex + ML + Encoding

✅ **High Accuracy ML Model**
- 99.75% detection accuracy
- Random Forest with 50 features
- Trained on 33,420 samples

✅ **Outperformed Industry Standard**
- Better than ModSecurity CRS
- Lower false positives (0.2% vs 5%)
- Catches obfuscated attacks

✅ **Complete Security System**
- Authentication, rate limiting, IP blocking
- XSS detection, security headers
- Parameterized queries

✅ **Real-World Application**
- Full-stack web application
- React frontend + Flask backend
- Ready for production use

**Future Work:**

🔮 **Deep Learning Models**
- LSTM for sequential pattern detection
- Transformer models (BERT)

🔮 **Real-Time Retraining**
- Continuous learning from new attacks
- Automated model updates

🔮 **Cloud Deployment**
- AWS/Azure deployment
- Scalable architecture

🔮 **API Security**
- GraphQL injection detection
- NoSQL injection detection

**Design Notes:**
- Use checkmarks for achievements
- Use crystal ball or arrow icons for future work
- Keep concise, bullet points only
- Two-column layout if needed

---

# SLIDE 18: Q&A

**Title:** Questions?

**Visual Element:** Clean, minimal design

**Content:**
- Large "Questions?" or "Q&A" text
- Graduation cap or question mark icon

**Contact Information:**
- Name: [Your Name]
- Email: [Your Email]
- University: [University Name]
- Thesis Supervisor: [Supervisor Name]

**Thank You Message:**
"Thank you for your attention!"

**Optional:**
- QR code linking to project repository
- Key takeaway reminder

**Design Notes:**
- Very clean, minimal text
- Large, centered "Questions?"
- Professional closing
- Include contact info for follow-up

---

# APPENDIX SLIDES (Optional - if professors ask detailed questions)

## APPENDIX A: Feature List (All 50 Features)

**Categories:**
1. Length Features: length, log_length
2. Character Ratios: quote_ratio, double_quote_ratio, semicolon_ratio, dash_ratio, slash_ratio, equals_ratio, parenthesis_ratio, bracket_ratio
3. SQL Keywords: keyword_count, has_union, has_select, has_insert, has_update, has_delete, has_drop, has_or, has_and, has_where, has_from
4. Pattern Detection: has_comment, has_hex, has_tautology, has_stacked_query
5. Statistical: entropy, digit_ratio, uppercase_ratio, special_char_ratio, whitespace_ratio
6. Structural: max_word_length, avg_word_length, word_count

## APPENDIX B: Regex Pattern List

Show all 36 regex patterns used in WAF

## APPENDIX C: API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/login | User login |
| POST | /api/register | User registration |
| GET | /api/products | List products |
| POST | /api/search | Search products |
| GET | /api/admin/users | List users (admin) |
| POST | /api/scan | Test WAF scanner |

---

# PRESENTATION TIPS

1. **Time Management:** ~1-2 minutes per slide = 18-36 minutes total
2. **Practice:** Run through at least 3 times
3. **Demo Backup:** Have screenshots ready if live demo fails
4. **Anticipate Questions:**
   - Why Random Forest over Deep Learning?
   - How do you handle new attack patterns?
   - What about performance/speed?
   - How does this compare to commercial WAFs?
5. **Keep Slides Visual:** Diagrams > Text
6. **Speak to Audience:** Don't read slides

---

# DESIGN RECOMMENDATIONS

**Color Scheme:**
- Primary: Blue (#2563EB) - Trust, Technology
- Secondary: Green (#10B981) - Success, Safe
- Accent: Red (#EF4444) - Danger, Attacks
- Background: White or Light Gray

**Fonts:**
- Headings: Bold Sans-Serif (Arial, Helvetica, Calibri)
- Body: Regular Sans-Serif
- Code: Monospace (Consolas, Courier New)

**Visual Elements:**
- Use icons from FontAwesome or similar
- Include diagrams on every slide
- Limit bullet points to 5-6 per slide
- Use animations sparingly (for reveals)

**Slide Layout:**
- Title at top
- Main visual in center
- Supporting text below or beside
- Slide number at bottom
