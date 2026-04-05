"""Traditional Machine Learning SQL Injection Detector

This module implements feature-based ML detection using:
- Random Forest
- XGBoost (Gradient Boosting)
- Support Vector Machine
- Neural Network (MLP - Multi-Layer Perceptron)

Features extracted:
- Character frequency analysis
- SQL keyword presence
- Special character ratios
- String entropy
- Structural patterns
"""

import os
import re
import math
import pickle
import numpy as np
from collections import Counter
from typing import Dict, List, Tuple, Optional

# ML Libraries
try:
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.svm import SVC
    from sklearn.neural_network import MLPClassifier  # Neural Network
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
    from sklearn.preprocessing import StandardScaler
    import joblib
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("[WARNING] scikit-learn not installed. Run: pip install scikit-learn")

# Optional: XGBoost for better performance
try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False


# ============================================================
# FEATURE EXTRACTION
# ============================================================

# SQL Keywords to detect
SQL_KEYWORDS = [
    'select', 'union', 'insert', 'update', 'delete', 'drop', 'alter',
    'create', 'table', 'from', 'where', 'and', 'or', 'not', 'null',
    'like', 'in', 'between', 'join', 'inner', 'outer', 'left', 'right',
    'order', 'by', 'group', 'having', 'limit', 'offset', 'into',
    'values', 'set', 'as', 'on', 'is', 'exists', 'case', 'when', 'then',
    'else', 'end', 'cast', 'convert', 'concat', 'substring', 'char',
    'ascii', 'benchmark', 'sleep', 'waitfor', 'delay', 'exec', 'execute',
    'declare', 'cursor', 'fetch', 'open', 'close', 'truncate'
]

# SQL Functions commonly used in injection
SQL_FUNCTIONS = [
    'concat', 'substring', 'substr', 'mid', 'left', 'right', 'char',
    'ascii', 'ord', 'hex', 'unhex', 'md5', 'sha1', 'sha2', 'password',
    'encrypt', 'compress', 'uncompress', 'benchmark', 'sleep',
    'version', 'database', 'user', 'current_user', 'system_user',
    'session_user', '@@version', 'load_file', 'outfile', 'dumpfile',
    'extractvalue', 'updatexml', 'exp', 'floor', 'rand', 'count',
    'group_concat', 'information_schema', 'pg_sleep', 'dbms_pipe'
]

# Special characters significant in SQL injection
SPECIAL_CHARS = ["'", '"', ';', '--', '/*', '*/', '#', '(', ')', '=', '<', '>', '|', '&', '+', '%']


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    
    counter = Counter(text)
    length = len(text)
    entropy = 0.0
    
    for count in counter.values():
        if count > 0:
            probability = count / length
            entropy -= probability * math.log2(probability)
    
    return entropy


def extract_features(text: str) -> np.ndarray:
    """
    Extract features from input text for ML classification.
    
    Returns a numpy array of features.
    """
    if not text:
        return np.zeros(50)  # Return zero vector for empty input
    
    text_lower = text.lower()
    text_len = len(text) if len(text) > 0 else 1  # Avoid division by zero
    
    features = []
    
    # ============ LENGTH FEATURES ============
    features.append(len(text))  # 1. Total length
    features.append(len(text.split()))  # 2. Word count
    
    # ============ CHARACTER FREQUENCY FEATURES ============
    # 3-7. Special SQL characters ratios
    features.append(text.count("'") / text_len)  # Single quote ratio
    features.append(text.count('"') / text_len)  # Double quote ratio
    features.append(text.count(';') / text_len)  # Semicolon ratio
    features.append(text.count('(') / text_len)  # Open paren ratio
    features.append(text.count(')') / text_len)  # Close paren ratio
    
    # 8-12. More special characters
    features.append(text.count('=') / text_len)  # Equals ratio
    features.append(text.count('-') / text_len)  # Dash ratio
    features.append(text.count('#') / text_len)  # Hash ratio
    features.append(text.count('*') / text_len)  # Asterisk ratio
    features.append(text.count('/') / text_len)  # Slash ratio
    
    # 13-15. Comment patterns
    features.append(1 if '--' in text else 0)  # SQL comment
    features.append(1 if '/*' in text else 0)  # Block comment start
    features.append(1 if '*/' in text else 0)  # Block comment end
    
    # ============ SQL KEYWORD FEATURES ============
    # 16. Total SQL keyword count
    keyword_count = sum(1 for kw in SQL_KEYWORDS if re.search(r'\b' + kw + r'\b', text_lower))
    features.append(keyword_count)
    
    # 17-26. Specific high-risk keyword presence
    high_risk_keywords = ['select', 'union', 'insert', 'update', 'delete', 
                          'drop', 'or', 'and', 'exec', 'execute']
    for kw in high_risk_keywords:
        features.append(1 if re.search(r'\b' + kw + r'\b', text_lower) else 0)
    
    # 27. SQL function count
    function_count = sum(1 for fn in SQL_FUNCTIONS if fn in text_lower)
    features.append(function_count)
    
    # ============ PATTERN FEATURES ============
    # 28. OR pattern (common in boolean injection)
    features.append(1 if re.search(r"['\"]?\s*or\s*['\"]?\d+['\"]?\s*=\s*['\"]?\d+", text_lower) else 0)
    
    # 29. AND pattern
    features.append(1 if re.search(r"['\"]?\s*and\s*['\"]?\d+['\"]?\s*=\s*['\"]?\d+", text_lower) else 0)
    
    # 30. UNION SELECT pattern
    features.append(1 if re.search(r'union\s+(all\s+)?select', text_lower) else 0)
    
    # 31. String termination pattern
    features.append(1 if re.search(r"['\"](\s*|\s*\))+(\s*--|\s*#|\s*/\*)", text) else 0)
    
    # 32. Stacked query pattern
    features.append(1 if re.search(r';\s*(select|insert|update|delete|drop|exec)', text_lower) else 0)
    
    # 33. Time-based injection pattern
    features.append(1 if re.search(r'(sleep|benchmark|waitfor|pg_sleep)\s*\(', text_lower) else 0)
    
    # 34. Information schema access
    features.append(1 if 'information_schema' in text_lower else 0)
    
    # 35. System table access
    features.append(1 if re.search(r'(sysobjects|syscolumns|sys\.|mysql\.|pg_)', text_lower) else 0)
    
    # ============ ENCODING FEATURES ============
    # 36. URL encoded characters
    features.append(len(re.findall(r'%[0-9a-fA-F]{2}', text)) / text_len)
    
    # 37. Hex encoded strings
    features.append(1 if re.search(r'0x[0-9a-fA-F]+', text) else 0)
    
    # 38. CHAR() function usage
    features.append(1 if re.search(r'char\s*\(\s*\d+', text_lower) else 0)
    
    # ============ STRUCTURAL FEATURES ============
    # 39. Quote balance (unbalanced often indicates injection)
    single_quotes = text.count("'")
    double_quotes = text.count('"')
    features.append(single_quotes % 2)  # Odd = unbalanced
    
    # 40. Parenthesis balance
    open_parens = text.count('(')
    close_parens = text.count(')')
    features.append(abs(open_parens - close_parens))
    
    # 41. Entropy (randomness measure)
    features.append(calculate_entropy(text))
    
    # 42. Uppercase ratio
    uppercase_count = sum(1 for c in text if c.isupper())
    features.append(uppercase_count / text_len)
    
    # 43. Digit ratio
    digit_count = sum(1 for c in text if c.isdigit())
    features.append(digit_count / text_len)
    
    # 44. Special char ratio (total)
    special_count = sum(1 for c in text if not c.isalnum() and not c.isspace())
    features.append(special_count / text_len)
    
    # 45. Whitespace ratio
    whitespace_count = sum(1 for c in text if c.isspace())
    features.append(whitespace_count / text_len)
    
    # ============ ADVANCED PATTERN FEATURES ============
    # 46. Multiple spaces (obfuscation technique)
    features.append(1 if '  ' in text else 0)
    
    # 47. Tab character (whitespace bypass)
    features.append(1 if '\t' in text else 0)
    
    # 48. Newline character
    features.append(1 if '\n' in text or '\r' in text else 0)
    
    # 49. Null byte
    features.append(1 if '\x00' in text or '%00' in text else 0)
    
    # 50. Consecutive special characters
    features.append(len(re.findall(r"['\";=\-\(\)]{2,}", text)) / text_len)
    
    return np.array(features)


def get_feature_names() -> List[str]:
    """Return names of all features for interpretability."""
    return [
        'length', 'word_count',
        'single_quote_ratio', 'double_quote_ratio', 'semicolon_ratio',
        'open_paren_ratio', 'close_paren_ratio', 'equals_ratio',
        'dash_ratio', 'hash_ratio', 'asterisk_ratio', 'slash_ratio',
        'has_sql_comment', 'has_block_comment_start', 'has_block_comment_end',
        'sql_keyword_count',
        'has_select', 'has_union', 'has_insert', 'has_update', 'has_delete',
        'has_drop', 'has_or', 'has_and', 'has_exec', 'has_execute',
        'sql_function_count',
        'or_pattern', 'and_pattern', 'union_select_pattern',
        'string_termination', 'stacked_query', 'time_based_pattern',
        'info_schema_access', 'system_table_access',
        'url_encoded_ratio', 'hex_encoded', 'char_function',
        'quote_unbalanced', 'paren_imbalance', 'entropy',
        'uppercase_ratio', 'digit_ratio', 'special_char_ratio', 'whitespace_ratio',
        'multiple_spaces', 'has_tab', 'has_newline', 'has_null_byte',
        'consecutive_special_ratio'
    ]


# ============================================================
# DATA LOADING
# ============================================================

def load_dataset(sqli_path: str, benign_path: str) -> Tuple[np.ndarray, np.ndarray]:
    """
    Load and prepare dataset from text files.
    
    Args:
        sqli_path: Path to SQL injection payloads file
        benign_path: Path to benign inputs file
    
    Returns:
        X: Feature matrix
        y: Labels (1 = SQLi, 0 = benign)
    """
    X = []
    y = []
    
    # Load SQL injection payloads
    if os.path.exists(sqli_path):
        with open(sqli_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    X.append(extract_features(line))
                    y.append(1)  # Malicious
        print(f"[INFO] Loaded {sum(y)} SQL injection payloads")
    else:
        print(f"[WARNING] SQLi payloads file not found: {sqli_path}")
    
    # Load benign inputs
    benign_count = 0
    if os.path.exists(benign_path):
        with open(benign_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    X.append(extract_features(line))
                    y.append(0)  # Benign
                    benign_count += 1
        print(f"[INFO] Loaded {benign_count} benign inputs")
    else:
        print(f"[WARNING] Benign inputs file not found: {benign_path}")
    
    return np.array(X), np.array(y)


# ============================================================
# MODEL TRAINING
# ============================================================

class SQLiMLDetector:
    """
    Machine Learning based SQL Injection Detector.
    
    Supports multiple classifiers:
    - Random Forest (default)
    - XGBoost
    - SVM
    - Neural Network (MLP)
    """
    
    def __init__(self, model_type: str = 'random_forest'):
        """
        Initialize detector.
        
        Args:
            model_type: 'random_forest', 'xgboost', 'svm', or 'neural_network'
        """
        self.model_type = model_type
        self.model = None
        self.scaler = StandardScaler() if ML_AVAILABLE else None
        self.is_trained = False
        self.feature_names = get_feature_names()
        
        # Initialize model based on type
        if ML_AVAILABLE:
            if model_type == 'random_forest':
                self.model = RandomForestClassifier(
                    n_estimators=100,
                    max_depth=20,
                    min_samples_split=5,
                    min_samples_leaf=2,
                    random_state=42,
                    n_jobs=-1
                )
            elif model_type == 'xgboost' and XGBOOST_AVAILABLE:
                self.model = xgb.XGBClassifier(
                    n_estimators=100,
                    max_depth=10,
                    learning_rate=0.1,
                    random_state=42,
                    use_label_encoder=False,
                    eval_metric='logloss'
                )
            elif model_type == 'svm':
                self.model = SVC(
                    kernel='rbf',
                    C=1.0,
                    gamma='scale',
                    probability=True,
                    random_state=42
                )
            elif model_type == 'gradient_boosting':
                self.model = GradientBoostingClassifier(
                    n_estimators=100,
                    max_depth=10,
                    learning_rate=0.1,
                    random_state=42
                )
            elif model_type == 'neural_network':
                # Multi-Layer Perceptron Neural Network
                self.model = MLPClassifier(
                    hidden_layer_sizes=(128, 64, 32),  # 3 hidden layers
                    activation='relu',                  # ReLU activation function
                    solver='adam',                      # Adam optimizer
                    alpha=0.0001,                       # L2 regularization
                    batch_size=32,                      # Mini-batch size
                    learning_rate='adaptive',           # Adaptive learning rate
                    learning_rate_init=0.001,           # Initial learning rate
                    max_iter=500,                       # Maximum iterations
                    early_stopping=True,                # Stop if validation score doesn't improve
                    validation_fraction=0.1,            # 10% for validation
                    n_iter_no_change=20,                # Stop after 20 iterations without improvement
                    random_state=42,
                    verbose=False
                )
            else:
                print(f"[WARNING] Unknown model type: {model_type}, using Random Forest")
                self.model = RandomForestClassifier(n_estimators=100, random_state=42)
    
    def train(self, X: np.ndarray, y: np.ndarray, test_size: float = 0.2) -> Dict:
        """
        Train the model.
        
        Args:
            X: Feature matrix
            y: Labels
            test_size: Fraction of data for testing
        
        Returns:
            Dictionary with training results and metrics
        """
        if not ML_AVAILABLE:
            return {"error": "scikit-learn not installed"}
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train model
        print(f"[INFO] Training {self.model_type} model...")
        self.model.fit(X_train_scaled, y_train)
        self.is_trained = True
        
        # Evaluate
        y_pred = self.model.predict(X_test_scaled)
        y_prob = self.model.predict_proba(X_test_scaled)[:, 1] if hasattr(self.model, 'predict_proba') else None
        
        # Calculate metrics
        accuracy = accuracy_score(y_test, y_pred)
        report = classification_report(y_test, y_pred, output_dict=True)
        cm = confusion_matrix(y_test, y_pred)
        
        # Cross-validation
        cv_scores = cross_val_score(self.model, X_train_scaled, y_train, cv=5)
        
        results = {
            "model_type": self.model_type,
            "accuracy": accuracy,
            "precision": report['1']['precision'] if '1' in report else 0,
            "recall": report['1']['recall'] if '1' in report else 0,
            "f1_score": report['1']['f1-score'] if '1' in report else 0,
            "confusion_matrix": cm.tolist(),
            "cv_scores": cv_scores.tolist(),
            "cv_mean": cv_scores.mean(),
            "cv_std": cv_scores.std(),
            "train_size": len(y_train),
            "test_size": len(y_test)
        }
        
        print(f"[INFO] Training complete!")
        print(f"  Accuracy: {accuracy:.4f}")
        print(f"  Precision: {results['precision']:.4f}")
        print(f"  Recall: {results['recall']:.4f}")
        print(f"  F1-Score: {results['f1_score']:.4f}")
        print(f"  CV Mean: {results['cv_mean']:.4f} (+/- {results['cv_std']:.4f})")
        
        return results
    
    def predict(self, text: str) -> Dict:
        """
        Predict if input is SQL injection.
        
        Args:
            text: Input string to analyze
        
        Returns:
            Dictionary with prediction and confidence
        """
        if not self.is_trained:
            return {"error": "Model not trained", "is_malicious": False, "confidence": 0.0}
        
        # Extract features
        features = extract_features(text).reshape(1, -1)
        features_scaled = self.scaler.transform(features)
        
        # Predict
        prediction = self.model.predict(features_scaled)[0]
        
        # Get confidence
        if hasattr(self.model, 'predict_proba'):
            probabilities = self.model.predict_proba(features_scaled)[0]
            confidence = probabilities[1] if prediction == 1 else probabilities[0]
        else:
            confidence = 1.0 if prediction == 1 else 0.0
        
        return {
            "is_malicious": bool(prediction == 1),
            "confidence": float(confidence),
            "prediction": int(prediction),
            "model_type": self.model_type
        }
    
    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance (for tree-based models)."""
        if not self.is_trained:
            return {}
        
        if hasattr(self.model, 'feature_importances_'):
            importances = self.model.feature_importances_
            return dict(zip(self.feature_names, importances.tolist()))
        
        return {}
    
    def save(self, path: str):
        """Save model to disk."""
        if not self.is_trained:
            print("[ERROR] Cannot save untrained model")
            return
        
        data = {
            'model': self.model,
            'scaler': self.scaler,
            'model_type': self.model_type,
            'feature_names': self.feature_names
        }
        
        joblib.dump(data, path)
        print(f"[INFO] Model saved to {path}")
    
    def load(self, path: str) -> bool:
        """Load model from disk."""
        if not os.path.exists(path):
            print(f"[ERROR] Model file not found: {path}")
            return False
        
        try:
            data = joblib.load(path)
            self.model = data['model']
            self.scaler = data['scaler']
            self.model_type = data['model_type']
            self.feature_names = data.get('feature_names', get_feature_names())
            self.is_trained = True
            print(f"[INFO] Model loaded from {path}")
            return True
        except Exception as e:
            print(f"[ERROR] Failed to load model: {e}")
            return False


# ============================================================
# CONVENIENCE FUNCTIONS
# ============================================================

def train_and_save_model(
    sqli_path: str,
    benign_path: str,
    output_path: str,
    model_type: str = 'random_forest'
) -> Dict:
    """
    Train a model and save it to disk.
    
    Args:
        sqli_path: Path to SQLi payloads file
        benign_path: Path to benign inputs file
        output_path: Path to save trained model
        model_type: Type of model to train
    
    Returns:
        Training results
    """
    # Load data
    X, y = load_dataset(sqli_path, benign_path)
    
    if len(X) == 0:
        return {"error": "No data loaded"}
    
    # Create and train model
    detector = SQLiMLDetector(model_type=model_type)
    results = detector.train(X, y)
    
    # Save model
    detector.save(output_path)
    
    return results


# ============================================================
# MAIN (for testing)
# ============================================================

if __name__ == "__main__":
    # Test feature extraction
    test_inputs = [
        "' OR '1'='1",
        "admin",
        "' UNION SELECT * FROM users--",
        "john_doe@example.com",
        "'; DROP TABLE users;--",
        "Hello, how are you?",
    ]
    
    print("=" * 60)
    print("SQL Injection ML Detector - Feature Extraction Test")
    print("=" * 60)
    
    for text in test_inputs:
        features = extract_features(text)
        print(f"\nInput: {text[:50]}...")
        print(f"  Features shape: {features.shape}")
        print(f"  Non-zero features: {np.count_nonzero(features)}")
        print(f"  Entropy: {features[40]:.4f}")
    
    print("\n" + "=" * 60)
    print("To train a model, run:")
    print("  python -c \"from ml_detector import train_and_save_model; train_and_save_model('data/sqli_payloads.txt', 'data/benign_inputs.txt', 'data/model.pkl')\"")
    print("=" * 60)
