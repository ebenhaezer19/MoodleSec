"""
CVSS v3.1 Base Score Calculator
Implements the official CVSS v3.1 specification for base score calculation.
"""

from typing import Dict
import re


# CVSS v3.1 Metric Values
METRICS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},  # Attack Vector
    "AC": {"L": 0.77, "H": 0.44},  # Attack Complexity
    "PR": {  # Privileges Required (depends on Scope)
        "N": {"U": 0.85, "C": 0.85},
        "L": {"U": 0.62, "C": 0.68},
        "H": {"U": 0.27, "C": 0.50}
    },
    "UI": {"N": 0.85, "R": 0.62},  # User Interaction
    "S": {"U": "Unchanged", "C": "Changed"},  # Scope
    "C": {"N": 0.0, "L": 0.22, "H": 0.56},  # Confidentiality Impact
    "I": {"N": 0.0, "L": 0.22, "H": 0.56},  # Integrity Impact
    "A": {"N": 0.0, "L": 0.22, "H": 0.56}   # Availability Impact
}


def parse_vector(vector: str) -> Dict[str, str]:
    """
    Parse CVSS v3.1 vector string into metric dictionary.
    
    Args:
        vector: CVSS vector string (e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        
    Returns:
        Dictionary of metric values
        
    Raises:
        ValueError: If vector format is invalid
    """
    if not vector.startswith("CVSS:3.1/"):
        raise ValueError("Vector must start with 'CVSS:3.1/'")
    
    # Remove prefix and split by /
    metrics_str = vector.replace("CVSS:3.1/", "")
    parts = metrics_str.split("/")
    
    metrics = {}
    for part in parts:
        if ":" not in part:
            raise ValueError(f"Invalid metric format: {part}")
        
        metric, value = part.split(":", 1)
        metrics[metric] = value
    
    # Validate required metrics
    required = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
    for req in required:
        if req not in metrics:
            raise ValueError(f"Missing required metric: {req}")
    
    # Validate metric values
    for metric, value in metrics.items():
        if metric == "PR":
            if value not in METRICS["PR"]:
                raise ValueError(f"Invalid value for {metric}: {value}")
        elif metric in METRICS:
            if value not in METRICS[metric]:
                raise ValueError(f"Invalid value for {metric}: {value}")
    
    return metrics


def calculate_impact(metrics: Dict[str, str]) -> float:
    """
    Calculate Impact Sub Score (ISS).
    
    Args:
        metrics: Dictionary of parsed CVSS metrics
        
    Returns:
        Impact score
    """
    c = METRICS["C"][metrics["C"]]
    i = METRICS["I"][metrics["I"]]
    a = METRICS["A"][metrics["A"]]
    
    iss_base = 1 - ((1 - c) * (1 - i) * (1 - a))
    
    if metrics["S"] == "U":  # Scope Unchanged
        impact = 6.42 * iss_base
    else:  # Scope Changed
        impact = 7.52 * (iss_base - 0.029) - 3.25 * pow(iss_base - 0.02, 15)
    
    return impact


def calculate_exploitability(metrics: Dict[str, str]) -> float:
    """
    Calculate Exploitability Sub Score.
    
    Args:
        metrics: Dictionary of parsed CVSS metrics
        
    Returns:
        Exploitability score
    """
    av = METRICS["AV"][metrics["AV"]]
    ac = METRICS["AC"][metrics["AC"]]
    
    # PR depends on Scope
    pr = METRICS["PR"][metrics["PR"]][metrics["S"]]
    
    ui = METRICS["UI"][metrics["UI"]]
    
    exploitability = 8.22 * av * ac * pr * ui
    
    return exploitability


def calculate_cvss(vector: str) -> float:
    """
    Calculate CVSS v3.1 Base Score from vector string.
    
    Args:
        vector: CVSS v3.1 vector string
        
    Returns:
        CVSS base score (0.0 - 10.0)
        
    Raises:
        ValueError: If vector format is invalid
        
    Example:
        >>> calculate_cvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        9.8
    """
    metrics = parse_vector(vector)
    
    impact = calculate_impact(metrics)
    exploitability = calculate_exploitability(metrics)
    
    # If Impact <= 0, score is 0
    if impact <= 0:
        return 0.0
    
    # Calculate base score
    if metrics["S"] == "U":  # Scope Unchanged
        base_score = min(impact + exploitability, 10.0)
    else:  # Scope Changed
        base_score = min(1.08 * (impact + exploitability), 10.0)
    
    # Round up to one decimal place
    base_score = round_up(base_score)
    
    return base_score


def round_up(value: float) -> float:
    """
    Round up to one decimal place (CVSS specification).
    
    Args:
        value: Value to round
        
    Returns:
        Rounded value
    """
    import math
    return math.ceil(value * 10) / 10


def severity(cvss_score: float) -> str:
    """
    Get severity rating from CVSS score.
    
    Args:
        cvss_score: CVSS base score (0.0 - 10.0)
        
    Returns:
        Severity rating string
        
    Example:
        >>> severity(9.8)
        'Critical'
    """
    if cvss_score == 0.0:
        return "None"
    elif cvss_score <= 3.9:
        return "Low"
    elif cvss_score <= 6.9:
        return "Medium"
    elif cvss_score <= 8.9:
        return "High"
    else:  # 9.0 - 10.0
        return "Critical"
