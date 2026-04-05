"""
ML Package for SQL Injection Detection

This package provides machine learning based detection of SQL injection attacks.

Modules:
    - ml_detector: Traditional ML (Random Forest, XGBoost, SVM)
    - deep_detector: Deep Learning (LSTM with attention) [coming soon]
    - ensemble_detector: Ensemble combining regex + ML + DL [coming soon]

Usage:
    from ml.ml_detector import SQLiMLDetector
    
    detector = SQLiMLDetector(model_type='random_forest')
    detector.load('path/to/model.pkl')
    result = detector.predict("' OR '1'='1")
    print(result['is_malicious'], result['confidence'])
"""

from .ml_detector import (
    SQLiMLDetector,
    extract_features,
    get_feature_names,
    load_dataset,
    train_and_save_model,
    ML_AVAILABLE,
    XGBOOST_AVAILABLE
)

__all__ = [
    'SQLiMLDetector',
    'extract_features',
    'get_feature_names',
    'load_dataset',
    'train_and_save_model',
    'ML_AVAILABLE',
    'XGBOOST_AVAILABLE'
]

__version__ = '1.0.0'
