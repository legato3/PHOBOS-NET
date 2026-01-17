"""Baseline tracking utilities for automatic, environment-specific metric baselines.

This module provides functions to track rolling baselines (mean and deviation) for key metrics,
enabling the system to distinguish normal background activity from abnormal behavior without
static thresholds or manual tuning.
"""
import time
from collections import deque
from app.core.app_state import _baselines, _baselines_lock, _baselines_last_update
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


def get_previous_hour_value(metric_name):
    """Get the value from approximately 1 hour ago (if available in baseline window).
    
    Since baselines update every 5 minutes, we look for a value from ~12 samples ago
    (12 * 5 min = 60 min). If not available, returns the oldest value in the window.
    
    Args:
        metric_name: One of 'active_flows', 'external_connections', 'firewall_blocks_rate', 'anomalies_rate'
    
    Returns:
        tuple: (value, is_approximate) or (None, False) if insufficient data
               is_approximate is True if we're using oldest value instead of exact 1-hour-ago
    """
    if metric_name not in _baselines:
        return (None, False)
    
    with _baselines_lock:
        values = list(_baselines[metric_name])
    
    if len(values) < 2:
        return (None, False)
    
    # Try to get value from ~1 hour ago (12 samples at 5-min intervals)
    # If window is smaller, use the second-to-last value (most recent previous value)
    # This allows trends to show even with minimal data
    if len(values) >= 12:
        # Full hour of data available
        return (values[-12], False)
    elif len(values) >= 2:
        # Use second-to-last value (previous sample)
        return (values[-2], True)  # Mark as approximate since it's not exactly 1 hour
    
    return (None, False)


def calculate_trend(metric_name, current_value, previous_value=None):
    """Calculate trend indicator comparing current value to previous hour.
    
    Respects baselines: small changes within normal range are muted.
    
    Args:
        metric_name: One of 'active_flows', 'external_connections', 'firewall_blocks_rate', 'anomalies_rate'
        current_value: Current metric value
        previous_value: Optional previous hour value (if None, will try to get from baseline)
                       Can be a tuple (value, is_approximate) or just a value
    
    Returns:
        dict: {
            'direction': 'up' | 'down' | 'stable',
            'indicator': '↑' | '↓' | '↔',
            'percent_change': float,
            'significant': bool,  # True if change is significant (outside normal variation)
            'muted': bool  # True if change should be visually muted
        }
        Returns None if insufficient data
    """
    if previous_value is None:
        prev_result = get_previous_hour_value(metric_name)
        if isinstance(prev_result, tuple):
            previous_value, is_approximate = prev_result
        else:
            previous_value = prev_result
            is_approximate = False
    else:
        is_approximate = False
    
    # Handle case where previous_value is 0 (can't divide by zero, but we can still show trend)
    if previous_value is None:
        return None
    
    # If previous value is 0 and current is > 0, that's a clear increase
    if previous_value == 0:
        if current_value > 0:
            return {
                'direction': 'up',
                'indicator': '↑',
                'percent_change': 100.0,  # Infinite change, show as 100%
                'significant': True,
                'muted': False
            }
        else:
            # Both are 0, no change
            return {
                'direction': 'stable',
                'indicator': '↔',
                'percent_change': 0.0,
                'significant': False,
                'muted': True
            }
    
    # Calculate percent change
    percent_change = ((current_value - previous_value) / previous_value) * 100
    
    # Get baseline stats to determine if change is significant
    stats = get_baseline_stats(metric_name)
    
    # Determine direction
    if abs(percent_change) < 1.0:  # Less than 1% change = stable
        direction = 'stable'
        indicator = '↔'
        significant = False
        muted = True
    elif percent_change > 0:
        direction = 'up'
        indicator = '↑'
        # Check if change is significant using baseline stddev
        if stats and stats['stddev'] > 0:
            # Change is significant if it's > 1 stddev from baseline mean
            change_magnitude = abs(current_value - stats['mean']) / stats['stddev']
            significant = change_magnitude > 1.0
            # Mute if change is small relative to baseline variation
            muted = abs(percent_change) < 5.0 or change_magnitude < 0.5
        else:
            # No baseline yet, use simple threshold: > 10% change is significant
            significant = abs(percent_change) > 10.0
            muted = abs(percent_change) < 5.0
    else:
        direction = 'down'
        indicator = '↓'
        # Check if change is significant using baseline stddev
        if stats and stats['stddev'] > 0:
            change_magnitude = abs(current_value - stats['mean']) / stats['stddev']
            significant = change_magnitude > 1.0
            muted = abs(percent_change) < 5.0 or change_magnitude < 0.5
        else:
            significant = abs(percent_change) > 10.0
            muted = abs(percent_change) < 5.0
    
    return {
        'direction': direction,
        'indicator': indicator,
        'percent_change': percent_change,
        'significant': significant,
        'muted': muted
    }
