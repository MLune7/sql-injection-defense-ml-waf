"""
Model Training Script for SQL Injection Detection

This script trains and evaluates ML models for SQLi detection.

Usage:
    python train_model.py                        # Train default Random Forest
    python train_model.py --model xgboost        # Train XGBoost
    python train_model.py --model svm            # Train SVM
    python train_model.py --model neural_network # Train Neural Network (MLP)
    python train_model.py --all                  # Train all models and compare
"""

import os
import sys
import json
import argparse
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml.ml_detector import (
    SQLiMLDetector, 
    load_dataset, 
    train_and_save_model,
    extract_features,
    get_feature_names,
    ML_AVAILABLE,
    XGBOOST_AVAILABLE
)


def get_data_paths():
    """Get paths to data files."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data_dir = os.path.join(base_dir, 'data')
    
    # Use expanded datasets if available, fall back to original
    sqli_expanded = os.path.join(data_dir, 'sqli_payloads_expanded.txt')
    benign_expanded = os.path.join(data_dir, 'benign_inputs_expanded.txt')
    
    sqli_file = sqli_expanded if os.path.exists(sqli_expanded) else os.path.join(data_dir, 'sqli_payloads.txt')
    benign_file = benign_expanded if os.path.exists(benign_expanded) else os.path.join(data_dir, 'benign_inputs.txt')
    
    return {
        'sqli': sqli_file,
        'benign': benign_file,
        'model_dir': data_dir
    }


def train_single_model(model_type: str, verbose: bool = True) -> dict:
    """Train a single model type."""
    paths = get_data_paths()
    
    if verbose:
        print(f"\n{'='*60}")
        print(f"Training {model_type.upper()} Model")
        print(f"{'='*60}")
    
    # Load data
    X, y = load_dataset(paths['sqli'], paths['benign'])
    
    if len(X) == 0:
        print("[ERROR] No data loaded!")
        return {"error": "No data loaded"}
    
    if verbose:
        print(f"\nDataset size: {len(X)} samples")
        print(f"  - Malicious: {sum(y)} ({sum(y)/len(y)*100:.1f}%)")
        print(f"  - Benign: {len(y)-sum(y)} ({(len(y)-sum(y))/len(y)*100:.1f}%)")
    
    # Train model
    detector = SQLiMLDetector(model_type=model_type)
    results = detector.train(X, y)
    
    # Save model
    model_path = os.path.join(paths['model_dir'], f'{model_type}_model.pkl')
    detector.save(model_path)
    
    # Get feature importance (if available)
    importance = detector.get_feature_importance()
    if importance and verbose:
        print("\nTop 10 Most Important Features:")
        sorted_importance = sorted(importance.items(), key=lambda x: x[1], reverse=True)[:10]
        for i, (name, score) in enumerate(sorted_importance, 1):
            print(f"  {i}. {name}: {score:.4f}")
    
    results['model_path'] = model_path
    results['feature_importance'] = importance
    
    return results


def train_all_models(verbose: bool = True) -> dict:
    """Train all available model types and compare."""
    models_to_train = ['random_forest', 'gradient_boosting', 'svm', 'neural_network']
    
    if XGBOOST_AVAILABLE:
        models_to_train.append('xgboost')
    
    results = {}
    
    print("\n" + "="*60)
    print("TRAINING ALL MODELS FOR COMPARISON")
    print("="*60)
    
    for model_type in models_to_train:
        try:
            results[model_type] = train_single_model(model_type, verbose=verbose)
        except Exception as e:
            print(f"[ERROR] Failed to train {model_type}: {e}")
            results[model_type] = {"error": str(e)}
    
    # Print comparison
    print("\n" + "="*60)
    print("MODEL COMPARISON")
    print("="*60)
    print(f"\n{'Model':<20} {'Accuracy':<10} {'Precision':<10} {'Recall':<10} {'F1-Score':<10}")
    print("-"*60)
    
    for model_type, res in results.items():
        if 'error' not in res:
            print(f"{model_type:<20} {res['accuracy']:<10.4f} {res['precision']:<10.4f} {res['recall']:<10.4f} {res['f1_score']:<10.4f}")
        else:
            print(f"{model_type:<20} ERROR: {res['error']}")
    
    # Find best model
    best_model = max(
        [(k, v) for k, v in results.items() if 'error' not in v],
        key=lambda x: x[1]['f1_score'],
        default=(None, None)
    )
    
    if best_model[0]:
        print(f"\n🏆 Best Model: {best_model[0].upper()} (F1-Score: {best_model[1]['f1_score']:.4f})")
    
    return results


def test_model(model_path: str, test_inputs: list = None):
    """Test a trained model with sample inputs."""
    if test_inputs is None:
        test_inputs = [
            # Malicious
            "' OR '1'='1",
            "' UNION SELECT * FROM users--",
            "'; DROP TABLE users;--",
            "' AND SLEEP(5)--",
            "admin'--",
            "1' OR 1=1#",
            
            # Benign
            "john_doe",
            "Hello, how are you?",
            "laptop computer",
            "john.doe@example.com",
            "O'Brien",
            "Select a product",
        ]
    
    detector = SQLiMLDetector()
    if not detector.load(model_path):
        print(f"[ERROR] Could not load model from {model_path}")
        return
    
    print("\n" + "="*60)
    print("MODEL TEST RESULTS")
    print("="*60)
    print(f"\n{'Input':<45} {'Prediction':<12} {'Confidence':<10}")
    print("-"*70)
    
    for text in test_inputs:
        result = detector.predict(text)
        prediction = "MALICIOUS" if result['is_malicious'] else "BENIGN"
        display_text = text[:42] + "..." if len(text) > 45 else text
        print(f"{display_text:<45} {prediction:<12} {result['confidence']:.4f}")


def save_training_report(results: dict, output_path: str):
    """Save training results to a JSON file."""
    report = {
        'timestamp': datetime.now().isoformat(),
        'results': results
    }
    
    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n[INFO] Training report saved to {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description='Train SQL Injection Detection Models',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python train_model.py                        # Train Random Forest (default)
    python train_model.py --model xgboost        # Train XGBoost
    python train_model.py --model svm            # Train SVM
    python train_model.py --model neural_network # Train Neural Network
    python train_model.py --all                  # Train all and compare
    python train_model.py --test             # Test trained model
        """
    )
    
    parser.add_argument(
        '--model', '-m',
        choices=['random_forest', 'xgboost', 'svm', 'gradient_boosting', 'neural_network'],
        default='random_forest',
        help='Model type to train (default: random_forest)'
    )
    
    parser.add_argument(
        '--all', '-a',
        action='store_true',
        help='Train all model types and compare'
    )
    
    parser.add_argument(
        '--test', '-t',
        action='store_true',
        help='Test the trained model with sample inputs'
    )
    
    parser.add_argument(
        '--report', '-r',
        type=str,
        help='Save training report to specified file'
    )
    
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Reduce output verbosity'
    )
    
    args = parser.parse_args()
    
    if not ML_AVAILABLE:
        print("[ERROR] scikit-learn is not installed!")
        print("Run: pip install scikit-learn numpy")
        sys.exit(1)
    
    # Check if data files exist
    paths = get_data_paths()
    if not os.path.exists(paths['sqli']):
        print(f"[ERROR] SQLi payloads file not found: {paths['sqli']}")
        sys.exit(1)
    if not os.path.exists(paths['benign']):
        print(f"[ERROR] Benign inputs file not found: {paths['benign']}")
        sys.exit(1)
    
    print("\n" + "="*60)
    print("SQL INJECTION ML DETECTOR - TRAINING")
    print("="*60)
    print(f"Data directory: {paths['model_dir']}")
    
    if args.all:
        results = train_all_models(verbose=not args.quiet)
        
        if args.report:
            save_training_report(results, args.report)
        
        # Test best model
        if args.test:
            best_model = max(
                [(k, v) for k, v in results.items() if 'error' not in v],
                key=lambda x: x[1]['f1_score'],
                default=(None, None)
            )
            if best_model[0]:
                test_model(best_model[1]['model_path'])
    
    else:
        results = train_single_model(args.model, verbose=not args.quiet)
        
        if args.report:
            save_training_report({args.model: results}, args.report)
        
        if args.test and 'model_path' in results:
            test_model(results['model_path'])
    
    print("\n" + "="*60)
    print("TRAINING COMPLETE")
    print("="*60)


if __name__ == "__main__":
    main()
