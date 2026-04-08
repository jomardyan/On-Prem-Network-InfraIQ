"""
Machine Learning-based network anomaly detection service.
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timezone, timedelta
import json
import statistics
from collections import defaultdict, deque

# Optional ML libraries
try:
    import numpy as np

    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False
    np = None

try:
    import pandas as pd

    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False
    pd = None

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    from sklearn.cluster import DBSCAN
    from sklearn.decomposition import PCA

    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False
    IsolationForest = None
    StandardScaler = None
    DBSCAN = None
    PCA = None

from ..core.models import ScanResult, HostInfo

logger = logging.getLogger(__name__)


class AnomalyType(str, Enum):
    """Types of network anomalies."""

    TRAFFIC_SPIKE = "traffic_spike"
    UNUSUAL_PORT = "unusual_port"
    NEW_DEVICE = "new_device"
    SUSPICIOUS_PATTERN = "suspicious_pattern"
    PROTOCOL_ANOMALY = "protocol_anomaly"
    TIMING_ANOMALY = "timing_anomaly"
    VOLUME_ANOMALY = "volume_anomaly"
    BEHAVIORAL_ANOMALY = "behavioral_anomaly"
    SECURITY_ANOMALY = "security_anomaly"


class AnomalySeverity(str, Enum):
    """Severity levels for anomalies."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class NetworkAnomaly:
    """Represents a detected network anomaly."""

    anomaly_type: AnomalyType
    severity: AnomalySeverity
    confidence: float
    description: str
    affected_hosts: List[str]
    timestamp: datetime
    features: Dict[str, Any]
    recommendation: str
    baseline_data: Dict[str, Any] = field(default_factory=dict)
    anomaly_score: float = 0.0


@dataclass
class NetworkMetrics:
    """Network metrics for anomaly detection."""

    timestamp: datetime
    host_count: int
    port_count: int
    service_count: int
    response_times: List[float]
    traffic_volume: float
    new_hosts: int
    failed_connections: int
    unique_services: Set[str] = field(default_factory=set)
    port_distribution: Dict[int, int] = field(default_factory=dict)
    host_activity: Dict[str, int] = field(default_factory=dict)


class NetworkAnomalyDetector:
    """
    Machine learning-based network anomaly detection system.

    This class provides advanced anomaly detection including:
    - Statistical anomaly detection
    - Machine learning-based pattern recognition
    - Behavioral analysis
    - Time-series anomaly detection
    - Network baseline establishment
    """

    def __init__(self, history_size: int = 1000, sensitivity: float = 0.1):
        """
        Initialize anomaly detector.

        Args:
            history_size: Number of historical data points to maintain
            sensitivity: Sensitivity threshold (0.0 to 1.0, lower = more sensitive)
        """
        self.history_size = history_size
        self.sensitivity = sensitivity
        self.logger = logging.getLogger(__name__)

        # Historical data storage
        self.metrics_history: deque = deque(maxlen=history_size)
        self.host_baseline: Dict[str, Dict[str, Any]] = {}
        self.service_baseline: Dict[str, Dict[str, Any]] = {}
        self.network_baseline: Dict[str, Any] = {}

        # ML models (initialized when needed)
        self.isolation_forest: Optional[Any] = None
        self.scaler: Optional[Any] = None
        self.dbscan: Optional[Any] = None

        # Statistics tracking
        self.anomaly_stats: Dict[str, Any] = {
            "total_anomalies": 0,
            "anomaly_types": defaultdict(int),
            "severity_distribution": defaultdict(int),
            "false_positives": 0,
            "confirmed_anomalies": 0,
        }

    async def analyze_network_data(self, scan_results: List[ScanResult]) -> List[NetworkAnomaly]:
        """
        Analyze network scan results for anomalies.

        Args:
            scan_results: List of network scan results

        Returns:
            List of detected anomalies
        """
        anomalies = []

        try:
            # Extract metrics from scan results
            metrics = self._extract_metrics(scan_results)

            # Add to history
            self.metrics_history.append(metrics)

            # Update baselines
            await self._update_baselines(metrics)

            # Detect anomalies using various methods
            statistical_anomalies = await self._detect_statistical_anomalies(metrics)
            anomalies.extend(statistical_anomalies)

            if HAS_SKLEARN and len(self.metrics_history) > 10:
                ml_anomalies = await self._detect_ml_anomalies(metrics)
                anomalies.extend(ml_anomalies)

            behavioral_anomalies = await self._detect_behavioral_anomalies(metrics)
            anomalies.extend(behavioral_anomalies)

            temporal_anomalies = await self._detect_temporal_anomalies(metrics)
            anomalies.extend(temporal_anomalies)

            # Update statistics
            self._update_anomaly_stats(anomalies)

            self.logger.info(f"Detected {len(anomalies)} anomalies in network data")

        except Exception as e:
            self.logger.error(f"Error analyzing network data: {e}")

        return anomalies

    def _extract_metrics(self, scan_results: List[ScanResult]) -> NetworkMetrics:
        """Extract metrics from scan results."""
        hosts = set()
        ports = set()
        services = set()
        response_times = []
        port_dist = defaultdict(int)
        host_activity = defaultdict(int)

        for result in scan_results:
            hosts.add(str(result.ip_address))
            ports.add(result.port)
            services.add(result.service_name)

            if result.ping_time is not None:
                response_times.append(result.ping_time)

            port_dist[result.port] += 1
            host_activity[str(result.ip_address)] += 1

        return NetworkMetrics(
            timestamp=datetime.now(timezone.utc),
            host_count=len(hosts),
            port_count=len(ports),
            service_count=len(services),
            response_times=response_times,
            traffic_volume=sum(response_times) if response_times else 0,
            new_hosts=0,  # Will be calculated in baseline update
            failed_connections=sum(1 for r in scan_results if not r.is_open),
            unique_services=services,
            port_distribution=dict(port_dist),
            host_activity=dict(host_activity),
        )

    async def _update_baselines(self, metrics: NetworkMetrics):
        """Update baseline data for anomaly detection."""
        if not self.network_baseline:
            # Initialize baseline
            self.network_baseline = {
                "avg_host_count": metrics.host_count,
                "avg_port_count": metrics.port_count,
                "avg_service_count": metrics.service_count,
                "avg_response_time": (
                    statistics.mean(metrics.response_times) if metrics.response_times else 0
                ),
                "common_ports": set(metrics.port_distribution.keys()),
                "common_services": metrics.unique_services.copy(),
                "established_hosts": set(metrics.host_activity.keys()),
                "last_updated": datetime.now(timezone.utc),
            }
        else:
            # Update baseline with exponential smoothing
            alpha = 0.1  # Smoothing factor

            self.network_baseline["avg_host_count"] = (
                alpha * metrics.host_count + (1 - alpha) * self.network_baseline["avg_host_count"]
            )

            self.network_baseline["avg_port_count"] = (
                alpha * metrics.port_count + (1 - alpha) * self.network_baseline["avg_port_count"]
            )

            self.network_baseline["avg_service_count"] = (
                alpha * metrics.service_count
                + (1 - alpha) * self.network_baseline["avg_service_count"]
            )

            if metrics.response_times:
                avg_response = statistics.mean(metrics.response_times)
                self.network_baseline["avg_response_time"] = (
                    alpha * avg_response + (1 - alpha) * self.network_baseline["avg_response_time"]
                )

            # Update common ports and services
            self.network_baseline["common_ports"].update(metrics.port_distribution.keys())
            self.network_baseline["common_services"].update(metrics.unique_services)

            # Track new hosts
            established_hosts = self.network_baseline["established_hosts"]
            current_hosts = set(metrics.host_activity.keys())
            metrics.new_hosts = len(current_hosts - established_hosts)

            # Update established hosts
            established_hosts.update(current_hosts)

            self.network_baseline["last_updated"] = datetime.now(timezone.utc)

    async def _detect_statistical_anomalies(self, metrics: NetworkMetrics) -> List[NetworkAnomaly]:
        """Detect anomalies using statistical methods."""
        anomalies = []

        if len(self.metrics_history) < 5:
            return anomalies  # Need more data

        try:
            # Host count anomaly
            host_counts = [m.host_count for m in self.metrics_history]
            if self._is_statistical_outlier(metrics.host_count, host_counts):
                anomalies.append(
                    NetworkAnomaly(
                        anomaly_type=AnomalyType.TRAFFIC_SPIKE,
                        severity=AnomalySeverity.MEDIUM,
                        confidence=0.8,
                        description=f"Unusual host count: {metrics.host_count} (baseline: {statistics.mean(host_counts):.1f})",
                        affected_hosts=list(metrics.host_activity.keys()),
                        timestamp=metrics.timestamp,
                        features={
                            "host_count": metrics.host_count,
                            "baseline": statistics.mean(host_counts),
                        },
                        recommendation="Investigate sudden change in network activity",
                    )
                )

            # Response time anomaly
            if metrics.response_times:
                avg_response = statistics.mean(metrics.response_times)
                historical_responses = []
                for m in self.metrics_history:
                    if m.response_times:
                        historical_responses.append(statistics.mean(m.response_times))

                if historical_responses and self._is_statistical_outlier(
                    avg_response, historical_responses
                ):
                    severity = (
                        AnomalySeverity.HIGH
                        if avg_response > statistics.mean(historical_responses) * 2
                        else AnomalySeverity.MEDIUM
                    )
                    anomalies.append(
                        NetworkAnomaly(
                            anomaly_type=AnomalyType.TIMING_ANOMALY,
                            severity=severity,
                            confidence=0.7,
                            description=f"Unusual response time: {avg_response:.2f}ms (baseline: {statistics.mean(historical_responses):.2f}ms)",
                            affected_hosts=list(metrics.host_activity.keys()),
                            timestamp=metrics.timestamp,
                            features={
                                "response_time": avg_response,
                                "baseline": statistics.mean(historical_responses),
                            },
                            recommendation="Check network performance and connectivity",
                        )
                    )

            # New hosts anomaly
            if metrics.new_hosts > 0:
                new_host_counts = [m.new_hosts for m in self.metrics_history[-10:]]
                if self._is_statistical_outlier(
                    metrics.new_hosts, new_host_counts + [metrics.new_hosts]
                ):
                    anomalies.append(
                        NetworkAnomaly(
                            anomaly_type=AnomalyType.NEW_DEVICE,
                            severity=AnomalySeverity.MEDIUM,
                            confidence=0.9,
                            description=f"Unusual number of new hosts: {metrics.new_hosts}",
                            affected_hosts=list(metrics.host_activity.keys()),
                            timestamp=metrics.timestamp,
                            features={"new_hosts": metrics.new_hosts},
                            recommendation="Verify legitimacy of new devices on network",
                        )
                    )

            # Port distribution anomaly
            if self.network_baseline.get("common_ports"):
                uncommon_ports = (
                    set(metrics.port_distribution.keys()) - self.network_baseline["common_ports"]
                )
                if uncommon_ports:
                    anomalies.append(
                        NetworkAnomaly(
                            anomaly_type=AnomalyType.UNUSUAL_PORT,
                            severity=AnomalySeverity.MEDIUM,
                            confidence=0.6,
                            description=f"Unusual ports detected: {list(uncommon_ports)}",
                            affected_hosts=list(metrics.host_activity.keys()),
                            timestamp=metrics.timestamp,
                            features={"unusual_ports": list(uncommon_ports)},
                            recommendation="Investigate unusual port usage for potential security threats",
                        )
                    )

        except Exception as e:
            self.logger.error(f"Error in statistical anomaly detection: {e}")

        return anomalies

    def _is_statistical_outlier(self, value: float, historical_values: List[float]) -> bool:
        """Check if value is a statistical outlier."""
        if len(historical_values) < 3:
            return False

        try:
            mean = statistics.mean(historical_values)
            stdev = statistics.stdev(historical_values)

            if stdev == 0:
                return value != mean

            z_score = abs(value - mean) / stdev
            return z_score > (2.0 - self.sensitivity)  # Adjustable threshold

        except:
            return False

    async def _detect_ml_anomalies(self, metrics: NetworkMetrics) -> List[NetworkAnomaly]:
        """Detect anomalies using machine learning models."""
        anomalies = []

        if not HAS_SKLEARN:
            return anomalies

        try:
            # Prepare feature matrix
            features = self._prepare_features_for_ml()

            if len(features) < 10:
                return anomalies

            # Train/update isolation forest
            if self.isolation_forest is None:
                self.isolation_forest = IsolationForest(
                    contamination=self.sensitivity, random_state=42
                )
                self.scaler = StandardScaler()

                # Fit scaler and model
                scaled_features = self.scaler.fit_transform(features)
                self.isolation_forest.fit(scaled_features)
            else:
                # Update with new data
                scaled_features = self.scaler.transform(features)

            # Predict anomalies for current metrics
            current_features = self._metrics_to_features(metrics)
            current_scaled = self.scaler.transform([current_features])

            anomaly_score = self.isolation_forest.decision_function(current_scaled)[0]
            is_anomaly = self.isolation_forest.predict(current_scaled)[0] == -1

            if is_anomaly:
                severity = self._determine_severity_from_score(anomaly_score)
                anomalies.append(
                    NetworkAnomaly(
                        anomaly_type=AnomalyType.BEHAVIORAL_ANOMALY,
                        severity=severity,
                        confidence=min(abs(anomaly_score), 1.0),
                        description=f"ML-detected behavioral anomaly (score: {anomaly_score:.3f})",
                        affected_hosts=list(metrics.host_activity.keys()),
                        timestamp=metrics.timestamp,
                        features={"ml_score": anomaly_score, "features": current_features},
                        recommendation="Investigate unusual network behavior pattern",
                        anomaly_score=anomaly_score,
                    )
                )

        except Exception as e:
            self.logger.error(f"Error in ML anomaly detection: {e}")

        return anomalies

    def _prepare_features_for_ml(self) -> List[List[float]]:
        """Prepare feature matrix for ML models."""
        features = []

        for metrics in self.metrics_history:
            feature_vector = self._metrics_to_features(metrics)
            features.append(feature_vector)

        return features

    def _metrics_to_features(self, metrics: NetworkMetrics) -> List[float]:
        """Convert metrics to feature vector."""
        features = [
            metrics.host_count,
            metrics.port_count,
            metrics.service_count,
            statistics.mean(metrics.response_times) if metrics.response_times else 0,
            metrics.traffic_volume,
            metrics.new_hosts,
            metrics.failed_connections,
            len(metrics.unique_services),
            len(metrics.port_distribution),
            max(metrics.host_activity.values()) if metrics.host_activity else 0,
            statistics.stdev(metrics.response_times) if len(metrics.response_times) > 1 else 0,
            sum(1 for p in metrics.port_distribution.keys() if p > 1024),  # High ports
            sum(1 for p in metrics.port_distribution.keys() if p < 1024),  # Well-known ports
        ]

        return features

    def _determine_severity_from_score(self, score: float) -> AnomalySeverity:
        """Determine severity based on anomaly score."""
        abs_score = abs(score)

        if abs_score > 0.5:
            return AnomalySeverity.CRITICAL
        elif abs_score > 0.3:
            return AnomalySeverity.HIGH
        elif abs_score > 0.2:
            return AnomalySeverity.MEDIUM
        else:
            return AnomalySeverity.LOW

    async def _detect_behavioral_anomalies(self, metrics: NetworkMetrics) -> List[NetworkAnomaly]:
        """Detect behavioral anomalies."""
        anomalies = []

        try:
            # Check for suspicious patterns
            if metrics.failed_connections > metrics.host_count * 0.5:
                anomalies.append(
                    NetworkAnomaly(
                        anomaly_type=AnomalyType.SUSPICIOUS_PATTERN,
                        severity=AnomalySeverity.HIGH,
                        confidence=0.8,
                        description=f"High failure rate: {metrics.failed_connections} failed connections",
                        affected_hosts=list(metrics.host_activity.keys()),
                        timestamp=metrics.timestamp,
                        features={
                            "failure_rate": metrics.failed_connections / max(metrics.host_count, 1)
                        },
                        recommendation="Investigate potential network scanning or attack activity",
                    )
                )

            # Check for scanning patterns
            if len(metrics.port_distribution) > 50:  # Many different ports
                anomalies.append(
                    NetworkAnomaly(
                        anomaly_type=AnomalyType.SUSPICIOUS_PATTERN,
                        severity=AnomalySeverity.MEDIUM,
                        confidence=0.7,
                        description=f"Port scanning pattern detected: {len(metrics.port_distribution)} different ports",
                        affected_hosts=list(metrics.host_activity.keys()),
                        timestamp=metrics.timestamp,
                        features={"port_diversity": len(metrics.port_distribution)},
                        recommendation="Check for unauthorized port scanning activity",
                    )
                )

            # Check for unusual service distribution
            if len(metrics.unique_services) > 20:
                anomalies.append(
                    NetworkAnomaly(
                        anomaly_type=AnomalyType.PROTOCOL_ANOMALY,
                        severity=AnomalySeverity.LOW,
                        confidence=0.6,
                        description=f"Unusual service diversity: {len(metrics.unique_services)} different services",
                        affected_hosts=list(metrics.host_activity.keys()),
                        timestamp=metrics.timestamp,
                        features={"service_diversity": len(metrics.unique_services)},
                        recommendation="Verify if unusual services are legitimate",
                    )
                )

        except Exception as e:
            self.logger.error(f"Error in behavioral anomaly detection: {e}")

        return anomalies

    async def _detect_temporal_anomalies(self, metrics: NetworkMetrics) -> List[NetworkAnomaly]:
        """Detect temporal anomalies."""
        anomalies = []

        try:
            # Check for time-based patterns
            current_hour = metrics.timestamp.hour

            # Activity outside business hours
            if current_hour < 7 or current_hour > 19:  # Outside 7 AM - 7 PM
                if metrics.host_count > self.network_baseline.get("avg_host_count", 0) * 0.8:
                    anomalies.append(
                        NetworkAnomaly(
                            anomaly_type=AnomalyType.TIMING_ANOMALY,
                            severity=AnomalySeverity.MEDIUM,
                            confidence=0.6,
                            description=f"High activity outside business hours: {metrics.host_count} hosts active",
                            affected_hosts=list(metrics.host_activity.keys()),
                            timestamp=metrics.timestamp,
                            features={"hour": current_hour, "activity_level": metrics.host_count},
                            recommendation="Investigate after-hours network activity",
                        )
                    )

            # Weekend activity
            if metrics.timestamp.weekday() >= 5:  # Saturday or Sunday
                if metrics.host_count > self.network_baseline.get("avg_host_count", 0) * 0.7:
                    anomalies.append(
                        NetworkAnomaly(
                            anomaly_type=AnomalyType.TIMING_ANOMALY,
                            severity=AnomalySeverity.LOW,
                            confidence=0.5,
                            description=f"High weekend activity: {metrics.host_count} hosts active",
                            affected_hosts=list(metrics.host_activity.keys()),
                            timestamp=metrics.timestamp,
                            features={
                                "weekday": metrics.timestamp.weekday(),
                                "activity_level": metrics.host_count,
                            },
                            recommendation="Verify weekend network activity is authorized",
                        )
                    )

        except Exception as e:
            self.logger.error(f"Error in temporal anomaly detection: {e}")

        return anomalies

    def _update_anomaly_stats(self, anomalies: List[NetworkAnomaly]):
        """Update anomaly statistics."""
        self.anomaly_stats["total_anomalies"] += len(anomalies)

        for anomaly in anomalies:
            self.anomaly_stats["anomaly_types"][anomaly.anomaly_type] += 1
            self.anomaly_stats["severity_distribution"][anomaly.severity] += 1

    async def get_anomaly_report(self) -> Dict[str, Any]:
        """Get comprehensive anomaly detection report."""
        report = {
            "summary": {
                "total_anomalies": self.anomaly_stats["total_anomalies"],
                "data_points_analyzed": len(self.metrics_history),
                "baseline_established": bool(self.network_baseline),
                "ml_models_active": HAS_SKLEARN and self.isolation_forest is not None,
                "last_analysis": (
                    self.metrics_history[-1].timestamp.isoformat() if self.metrics_history else None
                ),
            },
            "statistics": dict(self.anomaly_stats),
            "baseline": self.network_baseline.copy() if self.network_baseline else {},
            "model_info": {
                "isolation_forest_trained": self.isolation_forest is not None,
                "scaler_fitted": self.scaler is not None,
                "feature_dimensions": (
                    len(self._metrics_to_features(self.metrics_history[-1]))
                    if self.metrics_history
                    else 0
                ),
                "sensitivity": self.sensitivity,
            },
            "recommendations": [
                "Monitor anomalies with high confidence scores",
                "Investigate recurring anomaly patterns",
                "Adjust sensitivity based on false positive rate",
                "Regular baseline updates for evolving networks",
                "Consider whitelist for known anomalous but legitimate activity",
            ],
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        # Convert sets to lists for JSON serialization
        if "common_ports" in report["baseline"]:
            report["baseline"]["common_ports"] = list(report["baseline"]["common_ports"])
        if "common_services" in report["baseline"]:
            report["baseline"]["common_services"] = list(report["baseline"]["common_services"])
        if "established_hosts" in report["baseline"]:
            report["baseline"]["established_hosts"] = list(report["baseline"]["established_hosts"])

        return report

    async def train_model(self, historical_data: List[NetworkMetrics]):
        """Train anomaly detection models on historical data."""
        if not HAS_SKLEARN:
            self.logger.warning("scikit-learn not available, cannot train ML models")
            return

        try:
            # Add historical data to history
            self.metrics_history.extend(historical_data)

            # Prepare features
            features = self._prepare_features_for_ml()

            if len(features) < 10:
                self.logger.warning("Insufficient data for ML training")
                return

            # Train isolation forest
            self.isolation_forest = IsolationForest(
                contamination=self.sensitivity, random_state=42, n_estimators=100
            )

            self.scaler = StandardScaler()

            # Fit scaler and model
            scaled_features = self.scaler.fit_transform(features)
            self.isolation_forest.fit(scaled_features)

            self.logger.info(f"Trained anomaly detection model on {len(features)} samples")

        except Exception as e:
            self.logger.error(f"Error training ML model: {e}")

    async def update_sensitivity(self, new_sensitivity: float):
        """Update sensitivity and retrain model if needed."""
        if 0.0 <= new_sensitivity <= 1.0:
            self.sensitivity = new_sensitivity

            # Retrain isolation forest with new contamination rate
            if self.isolation_forest is not None and HAS_SKLEARN:
                features = self._prepare_features_for_ml()
                if len(features) >= 10:
                    self.isolation_forest = IsolationForest(
                        contamination=self.sensitivity, random_state=42, n_estimators=100
                    )
                    scaled_features = self.scaler.transform(features)
                    self.isolation_forest.fit(scaled_features)

            self.logger.info(f"Updated sensitivity to {new_sensitivity}")
        else:
            raise ValueError("Sensitivity must be between 0.0 and 1.0")

    async def mark_anomaly_feedback(self, anomaly_id: str, is_false_positive: bool):
        """Mark anomaly as false positive or confirmed for learning."""
        if is_false_positive:
            self.anomaly_stats["false_positives"] += 1
        else:
            self.anomaly_stats["confirmed_anomalies"] += 1

        # Future enhancement: Use feedback to improve model accuracy
        self.logger.info(
            f"Marked anomaly {anomaly_id} as {'false positive' if is_false_positive else 'confirmed'}"
        )

    def get_detection_accuracy(self) -> float:
        """Get current detection accuracy based on feedback."""
        total_feedback = (
            self.anomaly_stats["false_positives"] + self.anomaly_stats["confirmed_anomalies"]
        )

        if total_feedback == 0:
            return 0.0

        return self.anomaly_stats["confirmed_anomalies"] / total_feedback
