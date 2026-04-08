"""
Database integration module for persistent storage of scan results and analysis.
"""

import asyncio
import logging
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import sqlite3
import os
from contextlib import asynccontextmanager

# Optional SQLAlchemy imports
try:
    from sqlalchemy import (
        create_engine,
        Column,
        Integer,
        String,
        DateTime,
        Text,
        Boolean,
        Float,
        JSON,
    )
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy.orm import sessionmaker, Session
    from sqlalchemy.dialects.postgresql import UUID
    from sqlalchemy.sql import func
    from sqlalchemy.exc import SQLAlchemyError

    HAS_SQLALCHEMY = True
except ImportError:
    HAS_SQLALCHEMY = False
    create_engine = None
    Column = None
    Integer = None
    String = None
    DateTime = None
    Text = None
    Boolean = None
    Float = None
    JSON = None
    declarative_base = None
    sessionmaker = None
    Session = None
    UUID = None
    func = None
    SQLAlchemyError = None

from ..core.models import ScanResult, HostInfo, VulnerabilityResult, ScanSession, ScanStatistics
from ..security.ssl_analyzer import CertificateInfo
from ..security.web_scanner import WebScanResult
from ..services.anomaly_detector import NetworkAnomaly

logger = logging.getLogger(__name__)

# Database models
if HAS_SQLALCHEMY:
    Base = declarative_base()

    class ScanResultDB(Base):
        __tablename__ = "scan_results"

        id = Column(Integer, primary_key=True)
        session_id = Column(String(36), index=True)
        ip_address = Column(String(45), index=True)
        port = Column(Integer)
        is_open = Column(Boolean)
        service_name = Column(String(100))
        ping_time = Column(Float)
        operating_system = Column(String(100))
        server_info = Column(Text)
        discovered_at = Column(DateTime, default=func.now())
        country = Column(String(100))
        hostname = Column(String(255))
        is_vulnerable = Column(Boolean)
        vulnerability_info = Column(Text)
        service_version = Column(String(100))
        scan_type = Column(String(50))
        confidence = Column(Float)
        created_at = Column(DateTime, default=func.now())

    class HostInfoDB(Base):
        __tablename__ = "host_info"

        id = Column(Integer, primary_key=True)
        session_id = Column(String(36), index=True)
        ip_address = Column(String(45), index=True)
        hostname = Column(String(255))
        os_info = Column(String(200))
        mac_address = Column(String(17))
        response_time = Column(Float)
        is_reachable = Column(Boolean)
        discovered_at = Column(DateTime, default=func.now())
        scan_type = Column(String(50))
        geolocation = Column(JSON)
        network_info = Column(JSON)
        open_ports = Column(JSON)
        services = Column(JSON)
        created_at = Column(DateTime, default=func.now())

    class VulnerabilityDB(Base):
        __tablename__ = "vulnerabilities"

        id = Column(Integer, primary_key=True)
        session_id = Column(String(36), index=True)
        host = Column(String(45), index=True)
        port = Column(Integer)
        vulnerability_type = Column(String(100))
        severity = Column(String(20))
        title = Column(String(255))
        description = Column(Text)
        cve_id = Column(String(20))
        cvss_score = Column(Float)
        solution = Column(Text)
        references = Column(JSON)
        discovered_at = Column(DateTime, default=func.now())
        confidence = Column(Float)
        verified = Column(Boolean)
        created_at = Column(DateTime, default=func.now())

    class ScanSessionDB(Base):
        __tablename__ = "scan_sessions"

        id = Column(Integer, primary_key=True)
        session_id = Column(String(36), unique=True, index=True)
        name = Column(String(255))
        description = Column(Text)
        scan_type = Column(String(50))
        target_range = Column(String(100))
        start_time = Column(DateTime)
        end_time = Column(DateTime)
        duration = Column(Float)
        status = Column(String(20))
        configuration = Column(JSON)
        statistics = Column(JSON)
        created_at = Column(DateTime, default=func.now())

    class CertificateDB(Base):
        __tablename__ = "certificates"

        id = Column(Integer, primary_key=True)
        session_id = Column(String(36), index=True)
        hostname = Column(String(255), index=True)
        port = Column(Integer)
        subject = Column(JSON)
        issuer = Column(JSON)
        serial_number = Column(String(100))
        not_before = Column(DateTime)
        not_after = Column(DateTime)
        is_expired = Column(Boolean)
        days_until_expiry = Column(Integer)
        signature_algorithm = Column(String(100))
        public_key_algorithm = Column(String(100))
        public_key_size = Column(Integer)
        san_domains = Column(JSON)
        fingerprint_sha256 = Column(String(64))
        is_self_signed = Column(Boolean)
        security_level = Column(String(20))
        vulnerabilities = Column(JSON)
        created_at = Column(DateTime, default=func.now())

    class WebVulnerabilityDB(Base):
        __tablename__ = "web_vulnerabilities"

        id = Column(Integer, primary_key=True)
        session_id = Column(String(36), index=True)
        target_url = Column(String(500))
        vulnerability_type = Column(String(100))
        severity = Column(String(20))
        title = Column(String(255))
        description = Column(Text)
        url = Column(String(500))
        method = Column(String(10))
        parameter = Column(String(100))
        payload = Column(Text)
        evidence = Column(Text)
        recommendation = Column(Text)
        cwe_id = Column(String(20))
        owasp_category = Column(String(100))
        confidence = Column(Float)
        discovered_at = Column(DateTime, default=func.now())
        created_at = Column(DateTime, default=func.now())

    class AnomalyDB(Base):
        __tablename__ = "anomalies"

        id = Column(Integer, primary_key=True)
        session_id = Column(String(36), index=True)
        anomaly_type = Column(String(100))
        severity = Column(String(20))
        confidence = Column(Float)
        description = Column(Text)
        affected_hosts = Column(JSON)
        features = Column(JSON)
        recommendation = Column(Text)
        baseline_data = Column(JSON)
        anomaly_score = Column(Float)
        is_false_positive = Column(Boolean)
        timestamp = Column(DateTime, default=func.now())
        created_at = Column(DateTime, default=func.now())

else:
    # Fallback classes when SQLAlchemy is not available
    Base = None
    ScanResultDB = None
    HostInfoDB = None
    VulnerabilityDB = None
    ScanSessionDB = None
    CertificateDB = None
    WebVulnerabilityDB = None
    AnomalyDB = None


class DatabaseManager:
    """
    Database manager for persistent storage of network scan data.

    Supports both SQLite for lightweight deployments and PostgreSQL for production.
    """

    def __init__(self, database_url: str = "sqlite:///network_infraiq.db"):
        """
        Initialize database manager.

        Args:
            database_url: Database connection URL
        """
        self.database_url = database_url
        self.engine = None
        self.session_factory = None
        self.logger = logging.getLogger(__name__)

    async def initialize(self):
        """Initialize database connection and create tables."""
        if not HAS_SQLALCHEMY:
            self.logger.warning("SQLAlchemy not available, using fallback storage")
            return

        try:
            self.engine = create_engine(self.database_url, echo=False)
            self.session_factory = sessionmaker(bind=self.engine)

            # Create tables
            Base.metadata.create_all(self.engine)

            self.logger.info(f"Database initialized: {self.database_url}")

        except Exception as e:
            self.logger.error(f"Failed to initialize database: {e}")
            raise

    async def close(self):
        """Close database connection."""
        if self.engine:
            self.engine.dispose()
            self.logger.info("Database connection closed")

    @asynccontextmanager
    async def get_session(self):
        """Get database session context manager."""
        if not self.session_factory:
            raise RuntimeError("Database not initialized")

        session = self.session_factory()
        try:
            yield session
        except Exception as e:
            session.rollback()
            self.logger.error(f"Database session error: {e}")
            raise
        finally:
            session.close()

    async def save_scan_results(self, session_id: str, results: List[ScanResult]):
        """Save scan results to database."""
        if not HAS_SQLALCHEMY:
            await self._save_to_json_fallback("scan_results", session_id, results)
            return

        try:
            async with self.get_session() as session:
                for result in results:
                    db_result = ScanResultDB(
                        session_id=session_id,
                        ip_address=str(result.ip_address),
                        port=result.port,
                        is_open=result.is_open,
                        service_name=result.service_name,
                        ping_time=result.ping_time,
                        operating_system=result.operating_system,
                        server_info=result.server_info,
                        discovered_at=result.discovered_at,
                        country=result.country,
                        hostname=result.hostname,
                        is_vulnerable=result.is_vulnerable,
                        vulnerability_info=result.vulnerability_info,
                        service_version=result.service_version,
                        scan_type=getattr(result, "scan_type", "unknown"),
                        confidence=getattr(result, "confidence", 0.0),
                    )
                    session.add(db_result)

                session.commit()
                self.logger.info(f"Saved {len(results)} scan results for session {session_id}")

        except Exception as e:
            self.logger.error(f"Failed to save scan results: {e}")
            raise

    async def save_host_info(self, session_id: str, hosts: List[HostInfo]):
        """Save host information to database."""
        if not HAS_SQLALCHEMY:
            await self._save_to_json_fallback("host_info", session_id, hosts)
            return

        try:
            async with self.get_session() as session:
                for host in hosts:
                    db_host = HostInfoDB(
                        session_id=session_id,
                        ip_address=str(host.ip_address),
                        hostname=host.hostname,
                        os_info=host.os_info,
                        mac_address=host.mac_address,
                        response_time=host.response_time,
                        is_reachable=host.is_reachable,
                        discovered_at=host.discovered_at,
                        scan_type=host.scan_type,
                        geolocation=(
                            asdict(host.geolocation)
                            if hasattr(host, "geolocation") and host.geolocation
                            else None
                        ),
                        network_info=(
                            asdict(host.network_info)
                            if hasattr(host, "network_info") and host.network_info
                            else None
                        ),
                        open_ports=host.open_ports if hasattr(host, "open_ports") else None,
                        services=host.services if hasattr(host, "services") else None,
                    )
                    session.add(db_host)

                session.commit()
                self.logger.info(f"Saved {len(hosts)} host info records for session {session_id}")

        except Exception as e:
            self.logger.error(f"Failed to save host info: {e}")
            raise

    async def save_vulnerabilities(
        self, session_id: str, vulnerabilities: List[VulnerabilityResult]
    ):
        """Save vulnerability information to database."""
        if not HAS_SQLALCHEMY:
            await self._save_to_json_fallback("vulnerabilities", session_id, vulnerabilities)
            return

        try:
            async with self.get_session() as session:
                for vuln in vulnerabilities:
                    db_vuln = VulnerabilityDB(
                        session_id=session_id,
                        host=vuln.host,
                        port=vuln.port,
                        vulnerability_type=vuln.vulnerability_type,
                        severity=vuln.severity,
                        title=vuln.title,
                        description=vuln.description,
                        cve_id=vuln.cve_id,
                        cvss_score=vuln.cvss_score,
                        solution=vuln.solution,
                        references=vuln.references,
                        discovered_at=vuln.discovered_at,
                        confidence=vuln.confidence,
                        verified=vuln.verified,
                    )
                    session.add(db_vuln)

                session.commit()
                self.logger.info(
                    f"Saved {len(vulnerabilities)} vulnerabilities for session {session_id}"
                )

        except Exception as e:
            self.logger.error(f"Failed to save vulnerabilities: {e}")
            raise

    async def save_scan_session(self, session_data: ScanSession):
        """Save scan session information to database."""
        if not HAS_SQLALCHEMY:
            await self._save_to_json_fallback(
                "scan_sessions", session_data.session_id, [session_data]
            )
            return

        try:
            async with self.get_session() as session:
                db_session = ScanSessionDB(
                    session_id=session_data.session_id,
                    name=session_data.name,
                    description=session_data.description,
                    scan_type=session_data.scan_type,
                    target_range=session_data.target_range,
                    start_time=session_data.start_time,
                    end_time=session_data.end_time,
                    duration=session_data.duration,
                    status=session_data.status,
                    configuration=(
                        asdict(session_data.configuration) if session_data.configuration else None
                    ),
                    statistics=asdict(session_data.statistics) if session_data.statistics else None,
                )
                session.add(db_session)
                session.commit()

                self.logger.info(f"Saved scan session {session_data.session_id}")

        except Exception as e:
            self.logger.error(f"Failed to save scan session: {e}")
            raise

    async def save_certificates(self, session_id: str, certificates: List[CertificateInfo]):
        """Save certificate information to database."""
        if not HAS_SQLALCHEMY:
            await self._save_to_json_fallback("certificates", session_id, certificates)
            return

        try:
            async with self.get_session() as session:
                for cert in certificates:
                    db_cert = CertificateDB(
                        session_id=session_id,
                        hostname=cert.hostname,
                        port=cert.port,
                        subject=cert.subject,
                        issuer=cert.issuer,
                        serial_number=cert.serial_number,
                        not_before=cert.not_before,
                        not_after=cert.not_after,
                        is_expired=cert.is_expired,
                        days_until_expiry=cert.days_until_expiry,
                        signature_algorithm=cert.signature_algorithm,
                        public_key_algorithm=cert.public_key_algorithm,
                        public_key_size=cert.public_key_size,
                        san_domains=cert.san_domains,
                        fingerprint_sha256=cert.fingerprint_sha256,
                        is_self_signed=cert.is_self_signed,
                        security_level=cert.security_level,
                        vulnerabilities=cert.vulnerabilities,
                    )
                    session.add(db_cert)

                session.commit()
                self.logger.info(f"Saved {len(certificates)} certificates for session {session_id}")

        except Exception as e:
            self.logger.error(f"Failed to save certificates: {e}")
            raise

    async def save_web_vulnerabilities(self, session_id: str, scan_result: WebScanResult):
        """Save web vulnerability scan results to database."""
        if not HAS_SQLALCHEMY:
            await self._save_to_json_fallback("web_vulnerabilities", session_id, [scan_result])
            return

        try:
            async with self.get_session() as session:
                for vuln in scan_result.vulnerabilities:
                    db_vuln = WebVulnerabilityDB(
                        session_id=session_id,
                        target_url=scan_result.target_url,
                        vulnerability_type=vuln.vulnerability_type,
                        severity=vuln.severity,
                        title=vuln.title,
                        description=vuln.description,
                        url=vuln.url,
                        method=vuln.method,
                        parameter=vuln.parameter,
                        payload=vuln.payload,
                        evidence=vuln.evidence,
                        recommendation=vuln.recommendation,
                        cwe_id=vuln.cwe_id,
                        owasp_category=vuln.owasp_category,
                        confidence=vuln.confidence,
                        discovered_at=vuln.discovered_at,
                    )
                    session.add(db_vuln)

                session.commit()
                self.logger.info(
                    f"Saved {len(scan_result.vulnerabilities)} web vulnerabilities for session {session_id}"
                )

        except Exception as e:
            self.logger.error(f"Failed to save web vulnerabilities: {e}")
            raise

    async def save_anomalies(self, session_id: str, anomalies: List[NetworkAnomaly]):
        """Save network anomalies to database."""
        if not HAS_SQLALCHEMY:
            await self._save_to_json_fallback("anomalies", session_id, anomalies)
            return

        try:
            async with self.get_session() as session:
                for anomaly in anomalies:
                    db_anomaly = AnomalyDB(
                        session_id=session_id,
                        anomaly_type=anomaly.anomaly_type,
                        severity=anomaly.severity,
                        confidence=anomaly.confidence,
                        description=anomaly.description,
                        affected_hosts=anomaly.affected_hosts,
                        features=anomaly.features,
                        recommendation=anomaly.recommendation,
                        baseline_data=anomaly.baseline_data,
                        anomaly_score=anomaly.anomaly_score,
                        timestamp=anomaly.timestamp,
                    )
                    session.add(db_anomaly)

                session.commit()
                self.logger.info(f"Saved {len(anomalies)} anomalies for session {session_id}")

        except Exception as e:
            self.logger.error(f"Failed to save anomalies: {e}")
            raise

    async def get_scan_results(self, session_id: str, limit: int = 1000) -> List[Dict[str, Any]]:
        """Get scan results from database."""
        if not HAS_SQLALCHEMY:
            return await self._load_from_json_fallback("scan_results", session_id)

        try:
            async with self.get_session() as session:
                results = (
                    session.query(ScanResultDB)
                    .filter(ScanResultDB.session_id == session_id)
                    .limit(limit)
                    .all()
                )

                return [self._db_to_dict(result) for result in results]

        except Exception as e:
            self.logger.error(f"Failed to get scan results: {e}")
            return []

    async def get_vulnerabilities(
        self, session_id: str = None, severity: str = None, limit: int = 1000
    ) -> List[Dict[str, Any]]:
        """Get vulnerabilities from database."""
        if not HAS_SQLALCHEMY:
            return await self._load_from_json_fallback("vulnerabilities", session_id)

        try:
            async with self.get_session() as session:
                query = session.query(VulnerabilityDB)

                if session_id:
                    query = query.filter(VulnerabilityDB.session_id == session_id)

                if severity:
                    query = query.filter(VulnerabilityDB.severity == severity)

                results = query.limit(limit).all()

                return [self._db_to_dict(result) for result in results]

        except Exception as e:
            self.logger.error(f"Failed to get vulnerabilities: {e}")
            return []

    async def get_scan_sessions(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get scan sessions from database."""
        if not HAS_SQLALCHEMY:
            return await self._load_from_json_fallback("scan_sessions", None)

        try:
            async with self.get_session() as session:
                results = (
                    session.query(ScanSessionDB)
                    .order_by(ScanSessionDB.created_at.desc())
                    .limit(limit)
                    .all()
                )

                return [self._db_to_dict(result) for result in results]

        except Exception as e:
            self.logger.error(f"Failed to get scan sessions: {e}")
            return []

    async def get_statistics(self, session_id: str = None, days: int = 30) -> Dict[str, Any]:
        """Get scan statistics from database."""
        if not HAS_SQLALCHEMY:
            return await self._get_fallback_statistics(session_id, days)

        try:
            async with self.get_session() as session:
                cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)

                stats = {
                    "total_scans": 0,
                    "total_hosts": 0,
                    "total_vulnerabilities": 0,
                    "vulnerability_severity": {},
                    "scan_types": {},
                    "time_range": {
                        "start": cutoff_date.isoformat(),
                        "end": datetime.now(timezone.utc).isoformat(),
                    },
                }

                # Get session statistics
                session_query = session.query(ScanSessionDB).filter(
                    ScanSessionDB.created_at >= cutoff_date
                )

                if session_id:
                    session_query = session_query.filter(ScanSessionDB.session_id == session_id)

                sessions = session_query.all()
                stats["total_scans"] = len(sessions)

                # Get vulnerability statistics
                vuln_query = session.query(VulnerabilityDB).filter(
                    VulnerabilityDB.created_at >= cutoff_date
                )

                if session_id:
                    vuln_query = vuln_query.filter(VulnerabilityDB.session_id == session_id)

                vulnerabilities = vuln_query.all()
                stats["total_vulnerabilities"] = len(vulnerabilities)

                # Group by severity
                for vuln in vulnerabilities:
                    severity = vuln.severity
                    stats["vulnerability_severity"][severity] = (
                        stats["vulnerability_severity"].get(severity, 0) + 1
                    )

                # Group by scan type
                for scan_session in sessions:
                    scan_type = scan_session.scan_type
                    stats["scan_types"][scan_type] = stats["scan_types"].get(scan_type, 0) + 1

                # Get unique hosts
                host_query = (
                    session.query(HostInfoDB.ip_address)
                    .filter(HostInfoDB.created_at >= cutoff_date)
                    .distinct()
                )

                if session_id:
                    host_query = host_query.filter(HostInfoDB.session_id == session_id)

                stats["total_hosts"] = host_query.count()

                return stats

        except Exception as e:
            self.logger.error(f"Failed to get statistics: {e}")
            return {}

    async def cleanup_old_data(self, days: int = 90):
        """Clean up old data from database."""
        if not HAS_SQLALCHEMY:
            self.logger.info("Cleanup not available in fallback mode")
            return

        try:
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)

            async with self.get_session() as session:
                # Delete old scan results
                deleted_scans = (
                    session.query(ScanResultDB)
                    .filter(ScanResultDB.created_at < cutoff_date)
                    .delete()
                )

                # Delete old vulnerabilities
                deleted_vulns = (
                    session.query(VulnerabilityDB)
                    .filter(VulnerabilityDB.created_at < cutoff_date)
                    .delete()
                )

                # Delete old sessions
                deleted_sessions = (
                    session.query(ScanSessionDB)
                    .filter(ScanSessionDB.created_at < cutoff_date)
                    .delete()
                )

                session.commit()

                self.logger.info(
                    f"Cleaned up {deleted_scans} scan results, {deleted_vulns} vulnerabilities, {deleted_sessions} sessions"
                )

        except Exception as e:
            self.logger.error(f"Failed to cleanup old data: {e}")
            raise

    def _db_to_dict(self, db_obj) -> Dict[str, Any]:
        """Convert database object to dictionary."""
        result = {}

        for column in db_obj.__table__.columns:
            value = getattr(db_obj, column.name)
            if isinstance(value, datetime):
                result[column.name] = value.isoformat()
            else:
                result[column.name] = value

        return result

    async def _save_to_json_fallback(self, table_name: str, session_id: str, data: List[Any]):
        """Fallback to JSON file storage when SQLAlchemy is not available."""
        try:
            # Create data directory if it doesn't exist
            data_dir = "data"
            os.makedirs(data_dir, exist_ok=True)

            # Generate filename
            filename = f"{data_dir}/{table_name}_{session_id}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"

            # Convert data to JSON-serializable format
            json_data = []
            for item in data:
                if hasattr(item, "__dict__"):
                    json_data.append(
                        asdict(item) if hasattr(item, "__dataclass_fields__") else item.__dict__
                    )
                else:
                    json_data.append(item)

            # Save to JSON file
            with open(filename, "w") as f:
                json.dump(json_data, f, indent=2, default=str)

            self.logger.info(f"Saved {len(data)} records to {filename}")

        except Exception as e:
            self.logger.error(f"Failed to save to JSON fallback: {e}")

    async def _load_from_json_fallback(
        self, table_name: str, session_id: str
    ) -> List[Dict[str, Any]]:
        """Load data from JSON fallback files."""
        try:
            data_dir = "data"
            if not os.path.exists(data_dir):
                return []

            # Find matching files
            pattern = f"{table_name}_{session_id}_" if session_id else f"{table_name}_"
            files = [
                f for f in os.listdir(data_dir) if f.startswith(pattern) and f.endswith(".json")
            ]

            all_data = []
            for filename in files:
                filepath = os.path.join(data_dir, filename)
                with open(filepath, "r") as f:
                    file_data = json.load(f)
                    all_data.extend(file_data)

            return all_data

        except Exception as e:
            self.logger.error(f"Failed to load from JSON fallback: {e}")
            return []

    async def _get_fallback_statistics(self, session_id: str, days: int) -> Dict[str, Any]:
        """Get basic statistics from fallback storage."""
        try:
            stats = {
                "total_scans": 0,
                "total_hosts": 0,
                "total_vulnerabilities": 0,
                "vulnerability_severity": {},
                "scan_types": {},
                "time_range": {
                    "start": (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(),
                    "end": datetime.now(timezone.utc).isoformat(),
                },
            }

            # This is a simplified implementation for fallback mode
            # In a real implementation, you would parse the JSON files
            # and calculate statistics

            return stats

        except Exception as e:
            self.logger.error(f"Failed to get fallback statistics: {e}")
            return {}
