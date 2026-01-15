"""Baseline tracking utilities for automatic, environment-specific metric baselines.

This module provides functions to track rolling baselines (mean and deviation) for key metrics,
enabling the system to distinguish normal background activity from abnormal behavior without
static thresholds or manual tuning.
"""
import time
from collections import deque
from app.core.state import _baselines, _baselines_lock, _baselines_last_update
from app.config import (
    BASELINE_WINDOW_SIZE,
    BASELINE_UPDATE_INTERVAL,
    BASELINE_DEVIATION_MULTIPLIER
)


def update_baseline(metric_name, value, timestamp=None):
    """Update the rolling baseline for a metric.
    
    Args:
        metric_name: One of 'active_flows', 'external_connections', 'firewall_blocks_rate', 'anomalies_rate'
        value: The current metric value
        timestamp: Optional timestamp (defaults to current time)
    
    Returns:
        bool: True if baseline was updated, False if skipped (too soon since last update)
    """
    if metric_name not in _baselines:
        return False
    
    if timestamp is None:
        timestamp = time.time()
    
    # Check if enough time has passed since last update
    last_update = _baselines_last_update.get(metric_name, 0)
    if timestamp - last_update < BASELINE_UPDATE_INTERVAL:
        return False
    
    with _baselines_lock:
        _baselines[metric_name].append(value)
        _baselines_last_update[metric_name] = timestamp
        return True


def get_baseline_stats(metric_name):
    """Get baseline statistics (mean and standard deviation) for a metric.
    
    Args:
        metric_name: One of 'active_flows', 'external_connections', 'firewall_blocks_rate', 'anomalies_rate'
    
    Returns:
        dict: {'mean': float, 'stddev': float, 'count': int, 'min': float, 'max': float}
              Returns None if insufficient data (< 3 samples)
    """
    if metric_name not in _baselines:
        return None
    
    with _baselines_lock:
        values = list(_baselines[metric_name])
    
    if len(values) < 3:
        # Need at least 3 samples for meaningful statistics
        return None
    
    # Calculate mean
    mean = sum(values) / len(values)
    
    # Calculate standard deviation
    variance = sum((x - mean) ** 2 for x in values) / len(values)
    stddev = variance ** 0.5
    
    return {
        'mean': mean,
        'stddev': stddev,
        'count': len(values),
        'min': min(values),
        'max': max(values)
    }


def is_abnormal(metric_name, value):
    """Check if a metric value is abnormal compared to its baseline.
    
    Args:
        metric_name: One of 'active_flows', 'external_connections', 'firewall_blocks_rate', 'anomalies_rate'
        value: The current metric value to check
    
    Returns:
        dict: {
            'abnormal': bool,
            'deviation': float,  # Number of standard deviations from mean
            'baseline_mean': float,
            'baseline_stddev': float,
            'percent_change': float  # Percentage change from mean
        }
        Returns None if insufficient baseline data
    """
    stats = get_baseline_stats(metric_name)
    if stats is None:
        return None
    
    mean = stats['mean']
    stddev = stats['stddev']
    
    # Avoid division by zero
    if stddev == 0:
        # If no variation, any deviation is abnormal
        deviation = abs(value - mean) if mean > 0 else (1.0 if value > 0 else 0.0)
    else:
        deviation = abs(value - mean) / stddev
    
    abnormal = deviation >= BASELINE_DEVIATION_MULTIPLIER
    
    percent_change = ((value - mean) / mean * 100) if mean > 0 else 0.0
    
    return {
        'abnormal': abnormal,
        'deviation': deviation,
        'baseline_mean': mean,
        'baseline_stddev': stddev,
        'percent_change': percent_change
    }


def get_baseline_summary():
    """Get a summary of all baseline statistics.
    
    Returns:
        dict: {metric_name: stats_dict} for all metrics with sufficient data
    """
    summary = {}
    for metric_name in _baselines.keys():
        stats = get_baseline_stats(metric_name)
        if stats:
            summary[metric_name] = stats
    return summary
