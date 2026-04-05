#!/usr/bin/env python3
"""
WAF Benchmark Framework

Measures performance metrics for the ML-WAF system:
- Speed (latency per request)
- Throughput (requests per second)
- Memory usage
- Accuracy under load
- Comparison with/without WAF

Usage:
    python benchmark.py           # Quick benchmark (1000 samples)
    python benchmark.py --full    # Full benchmark (all samples)
    python benchmark.py --stress  # Stress test (10000 requests)
"""

import time
import sys
import os
import json
import random
import statistics
import tracemalloc
from typing import Dict, List, Tuple
from datetime import datetime
from dataclasses import dataclass, asdict

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from waf import detect_sqli_ensemble, detect_sqli, is_blacklisted


@dataclass
class BenchmarkResult:
    """Container for benchmark results."""
    timestamp: str
    total_samples: int
    total_time_seconds: float
    avg_latency_ms: float
    min_latency_ms: float
    max_latency_ms: float
    median_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float
    throughput_rps: float
    memory_peak_mb: float
    memory_current_mb: float
    
    # Accuracy metrics
    true_positives: int
    true_negatives: int
    false_positives: int
    false_negatives: int
    accuracy_percent: float
    precision_percent: float
    recall_percent: float
    f1_score_percent: float
    
    # Component breakdown
    blacklist_avg_ms: float
    regex_avg_ms: float
    ml_avg_ms: float
    ensemble_avg_ms: float


def load_test_data() -> List[Tuple[str, bool]]:
    """Load test data from the existing datasets."""
    test_data = []
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Load SQLi payloads (malicious)
    sqli_path = os.path.join(base_dir, "data", "sqli_payloads_expanded.txt")
    if os.path.exists(sqli_path):
        with open(sqli_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    test_data.append((line, True))
    
    # Load benign inputs
    benign_path = os.path.join(base_dir, "data", "benign_inputs_expanded.txt")
    if os.path.exists(benign_path):
        with open(benign_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    test_data.append((line, False))
    
    return test_data


def measure_component_speed(payloads: List[str], iterations: int = 100) -> Dict[str, float]:
    """Measure speed of individual WAF components."""
    
    # Blacklist timing
    start = time.perf_counter()
    for payload in payloads[:iterations]:
        is_blacklisted(payload)
    blacklist_time = (time.perf_counter() - start) * 1000 / iterations
    
    # Regex timing
    start = time.perf_counter()
    for payload in payloads[:iterations]:
        detect_sqli(payload)
    regex_time = (time.perf_counter() - start) * 1000 / iterations
    
    # Full ensemble timing
    start = time.perf_counter()
    for payload in payloads[:iterations]:
        detect_sqli_ensemble(payload)
    ensemble_time = (time.perf_counter() - start) * 1000 / iterations
    
    # ML time is approximately ensemble - (blacklist + regex)
    ml_time = max(0, ensemble_time - blacklist_time - regex_time)
    
    return {
        "blacklist_avg_ms": round(blacklist_time, 4),
        "regex_avg_ms": round(regex_time, 4),
        "ml_avg_ms": round(ml_time, 4),
        "ensemble_avg_ms": round(ensemble_time, 4)
    }


def run_benchmark(test_data: List[Tuple[str, bool]], description: str = "Standard") -> BenchmarkResult:
    """Run full benchmark on test data."""
    
    print(f"\n{'='*60}")
    print(f"RUNNING {description.upper()} BENCHMARK")
    print(f"{'='*60}")
    print(f"Samples: {len(test_data)}")
    
    # Start memory tracking
    tracemalloc.start()
    
    latencies = []
    tp, tn, fp, fn = 0, 0, 0, 0
    
    # Warm-up run (load ML model)
    print("Warming up ML model...")
    detect_sqli_ensemble("test warmup query")
    
    print("Running benchmark...")
    start_total = time.perf_counter()
    
    for i, (payload, is_malicious) in enumerate(test_data):
        # Measure single request
        start = time.perf_counter()
        result = detect_sqli_ensemble(payload)
        latency = (time.perf_counter() - start) * 1000  # Convert to ms
        latencies.append(latency)
        
        # Track accuracy
        detected = result["is_malicious"]
        if is_malicious and detected:
            tp += 1
        elif not is_malicious and not detected:
            tn += 1
        elif not is_malicious and detected:
            fp += 1
        else:
            fn += 1
        
        # Progress indicator
        if (i + 1) % 500 == 0:
            print(f"  Processed {i + 1}/{len(test_data)} samples...")
    
    total_time = time.perf_counter() - start_total
    
    # Get memory stats
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
    # Calculate metrics
    accuracy = (tp + tn) / len(test_data) * 100 if test_data else 0
    precision = tp / (tp + fp) * 100 if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) * 100 if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    # Component speed breakdown
    payloads = [p for p, _ in test_data]
    component_times = measure_component_speed(payloads)
    
    # Sort latencies for percentiles
    sorted_latencies = sorted(latencies)
    p95_idx = int(len(sorted_latencies) * 0.95)
    p99_idx = int(len(sorted_latencies) * 0.99)
    
    return BenchmarkResult(
        timestamp=datetime.now().isoformat(),
        total_samples=len(test_data),
        total_time_seconds=round(total_time, 2),
        avg_latency_ms=round(statistics.mean(latencies), 4),
        min_latency_ms=round(min(latencies), 4),
        max_latency_ms=round(max(latencies), 4),
        median_latency_ms=round(statistics.median(latencies), 4),
        p95_latency_ms=round(sorted_latencies[p95_idx], 4),
        p99_latency_ms=round(sorted_latencies[p99_idx], 4),
        throughput_rps=round(len(test_data) / total_time, 2),
        memory_peak_mb=round(peak / 1024 / 1024, 2),
        memory_current_mb=round(current / 1024 / 1024, 2),
        true_positives=tp,
        true_negatives=tn,
        false_positives=fp,
        false_negatives=fn,
        accuracy_percent=round(accuracy, 2),
        precision_percent=round(precision, 2),
        recall_percent=round(recall, 2),
        f1_score_percent=round(f1, 2),
        **component_times
    )


def print_benchmark_report(result: BenchmarkResult):
    """Print formatted benchmark report."""
    
    print(f"\n{'='*60}")
    print("BENCHMARK RESULTS")
    print(f"{'='*60}")
    print(f"Timestamp: {result.timestamp}")
    print(f"Total Samples: {result.total_samples:,}")
    
    print(f"\n{'-'*60}")
    print("PERFORMANCE METRICS")
    print(f"{'-'*60}")
    print(f"  Total Time:        {result.total_time_seconds} seconds")
    print(f"  Throughput:        {result.throughput_rps:,.2f} requests/second")
    print(f"  Avg Latency:       {result.avg_latency_ms:.4f} ms")
    print(f"  Min Latency:       {result.min_latency_ms:.4f} ms")
    print(f"  Max Latency:       {result.max_latency_ms:.4f} ms")
    print(f"  Median Latency:    {result.median_latency_ms:.4f} ms")
    print(f"  95th Percentile:   {result.p95_latency_ms:.4f} ms")
    print(f"  99th Percentile:   {result.p99_latency_ms:.4f} ms")
    
    print(f"\n{'-'*60}")
    print("MEMORY USAGE")
    print(f"{'-'*60}")
    print(f"  Peak Memory:       {result.memory_peak_mb:.2f} MB")
    print(f"  Current Memory:    {result.memory_current_mb:.2f} MB")
    
    print(f"\n{'-'*60}")
    print("COMPONENT BREAKDOWN (avg per request)")
    print(f"{'-'*60}")
    print(f"  Blacklist Check:   {result.blacklist_avg_ms:.4f} ms")
    print(f"  Regex Patterns:    {result.regex_avg_ms:.4f} ms")
    print(f"  ML Detection:      {result.ml_avg_ms:.4f} ms")
    print(f"  Total Ensemble:    {result.ensemble_avg_ms:.4f} ms")
    
    print(f"\n{'-'*60}")
    print("ACCURACY METRICS")
    print(f"{'-'*60}")
    print(f"  True Positives:    {result.true_positives:,}")
    print(f"  True Negatives:    {result.true_negatives:,}")
    print(f"  False Positives:   {result.false_positives:,}")
    print(f"  False Negatives:   {result.false_negatives:,}")
    print(f"  Accuracy:          {result.accuracy_percent:.2f}%")
    print(f"  Precision:         {result.precision_percent:.2f}%")
    print(f"  Recall:            {result.recall_percent:.2f}%")
    print(f"  F1 Score:          {result.f1_score_percent:.2f}%")
    
    print(f"\n{'-'*60}")
    print("PERFORMANCE ASSESSMENT")
    print(f"{'-'*60}")
    
    # Latency assessment
    if result.avg_latency_ms < 10:
        latency_grade = "EXCELLENT"
        latency_emoji = "✅"
    elif result.avg_latency_ms < 50:
        latency_grade = "GOOD"
        latency_emoji = "✅"
    elif result.avg_latency_ms < 100:
        latency_grade = "ACCEPTABLE"
        latency_emoji = "⚠️"
    else:
        latency_grade = "SLOW"
        latency_emoji = "❌"
    
    print(f"  Latency:           {latency_emoji} {latency_grade} ({result.avg_latency_ms:.2f}ms avg)")
    
    # Throughput assessment
    if result.throughput_rps > 1000:
        throughput_grade = "EXCELLENT"
        throughput_emoji = "✅"
    elif result.throughput_rps > 100:
        throughput_grade = "GOOD"
        throughput_emoji = "✅"
    elif result.throughput_rps > 10:
        throughput_grade = "ACCEPTABLE"
        throughput_emoji = "⚠️"
    else:
        throughput_grade = "LOW"
        throughput_emoji = "❌"
    
    print(f"  Throughput:        {throughput_emoji} {throughput_grade} ({result.throughput_rps:.0f} req/s)")
    
    # Memory assessment
    if result.memory_peak_mb < 100:
        memory_grade = "EXCELLENT"
        memory_emoji = "✅"
    elif result.memory_peak_mb < 500:
        memory_grade = "GOOD"
        memory_emoji = "✅"
    elif result.memory_peak_mb < 1000:
        memory_grade = "ACCEPTABLE"
        memory_emoji = "⚠️"
    else:
        memory_grade = "HIGH"
        memory_emoji = "❌"
    
    print(f"  Memory:            {memory_emoji} {memory_grade} ({result.memory_peak_mb:.0f}MB peak)")
    
    # Accuracy assessment
    if result.f1_score_percent > 95:
        accuracy_grade = "EXCELLENT"
        accuracy_emoji = "✅"
    elif result.f1_score_percent > 80:
        accuracy_grade = "GOOD"
        accuracy_emoji = "✅"
    elif result.f1_score_percent > 60:
        accuracy_grade = "ACCEPTABLE"
        accuracy_emoji = "⚠️"
    else:
        accuracy_grade = "POOR"
        accuracy_emoji = "❌"
    
    print(f"  Accuracy:          {accuracy_emoji} {accuracy_grade} ({result.f1_score_percent:.2f}% F1)")
    
    print(f"\n{'='*60}")


def run_stress_test(iterations: int = 10000) -> BenchmarkResult:
    """Run stress test with repeated requests."""
    
    print(f"\n{'='*60}")
    print("RUNNING STRESS TEST")
    print(f"{'='*60}")
    
    # Mix of attack and benign payloads
    test_payloads = [
        ("' OR '1'='1", True),
        ("hello world", False),
        ("SELECT * FROM users", True),
        ("john@email.com", False),
        ("'; DROP TABLE--", True),
        ("My product review", False),
        ("1 UNION SELECT *", True),
        ("password123", False),
        ("admin'--", True),
        ("Normal search query", False),
    ]
    
    # Repeat to reach iteration count
    full_test = test_payloads * (iterations // len(test_payloads) + 1)
    full_test = full_test[:iterations]
    
    random.shuffle(full_test)
    
    return run_benchmark(full_test, f"Stress Test ({iterations:,} requests)")


def main():
    print("\n" + "="*60)
    print("WAF BENCHMARK FRAMEWORK")
    print("="*60)
    
    # Parse arguments
    full_mode = "--full" in sys.argv
    stress_mode = "--stress" in sys.argv
    
    # Load test data
    print("\nLoading test data...")
    test_data = load_test_data()
    print(f"Loaded {len(test_data):,} samples")
    
    if not test_data:
        print("ERROR: No test data found!")
        return
    
    results = []
    
    if stress_mode:
        # Stress test
        stress_count = 10000
        result = run_stress_test(stress_count)
        results.append(("stress", result))
        print_benchmark_report(result)
        
    elif full_mode:
        # Full benchmark on all data
        result = run_benchmark(test_data, "Full Dataset")
        results.append(("full", result))
        print_benchmark_report(result)
        
    else:
        # Quick benchmark (1000 samples)
        random.seed(42)
        sample = random.sample(test_data, min(1000, len(test_data)))
        result = run_benchmark(sample, "Quick (1000 samples)")
        results.append(("quick", result))
        print_benchmark_report(result)
    
    # Save results
    output_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "benchmark_results_detailed.json"
    )
    
    with open(output_path, "w") as f:
        save_data = {name: asdict(result) for name, result in results}
        json.dump(save_data, f, indent=2)
    
    print(f"\nResults saved to: {output_path}")
    print("\nUsage:")
    print("  python benchmark.py           # Quick test (1000 samples)")
    print("  python benchmark.py --full    # Full test (all samples)")
    print("  python benchmark.py --stress  # Stress test (10000 requests)")


if __name__ == "__main__":
    main()
