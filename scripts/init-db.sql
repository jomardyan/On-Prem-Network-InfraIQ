-- On-Prem Network InfraIQ Database Schema
-- Professional enterprise-grade schema for storing scan results and configurations

-- Create database extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Organizations table for multi-tenant support
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    domain VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active BOOLEAN DEFAULT TRUE
);

-- Users table with role-based access control
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id),
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    role VARCHAR(50) DEFAULT 'analyst',
    last_login TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active BOOLEAN DEFAULT TRUE
);

-- Network assets registry
CREATE TABLE network_assets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id),
    ip_address INET NOT NULL,
    hostname VARCHAR(255),
    mac_address MACADDR,
    asset_type VARCHAR(50),
    operating_system VARCHAR(255),
    criticality_level VARCHAR(20) DEFAULT 'medium',
    owner VARCHAR(255),
    location VARCHAR(255),
    description TEXT,
    first_discovered TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active BOOLEAN DEFAULT TRUE
);

-- Scan sessions
CREATE TABLE scan_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id),
    user_id UUID REFERENCES users(id),
    name VARCHAR(255) NOT NULL,
    scan_type VARCHAR(50) NOT NULL,
    target_network CIDR,
    start_time TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    end_time TIMESTAMP WITH TIME ZONE,
    status VARCHAR(20) DEFAULT 'running',
    configuration JSONB,
    results_summary JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Network discoveries
CREATE TABLE network_discoveries (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_session_id UUID REFERENCES scan_sessions(id),
    asset_id UUID REFERENCES network_assets(id),
    ip_address INET NOT NULL,
    hostname VARCHAR(255),
    mac_address MACADDR,
    response_time INTEGER,
    operating_system VARCHAR(255),
    is_online BOOLEAN DEFAULT FALSE,
    discovered_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Port scan results
CREATE TABLE port_scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    discovery_id UUID REFERENCES network_discoveries(id),
    port_number INTEGER NOT NULL,
    protocol VARCHAR(10) DEFAULT 'tcp',
    state VARCHAR(20) NOT NULL,
    service_name VARCHAR(100),
    service_version VARCHAR(255),
    banner TEXT,
    scanned_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Vulnerability findings
CREATE TABLE vulnerabilities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_session_id UUID REFERENCES scan_sessions(id),
    asset_id UUID REFERENCES network_assets(id),
    cve_id VARCHAR(20),
    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL,
    cvss_score DECIMAL(3,1),
    cvss_vector VARCHAR(255),
    port_number INTEGER,
    service_name VARCHAR(100),
    evidence TEXT,
    recommendation TEXT,
    status VARCHAR(20) DEFAULT 'open',
    first_found TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_verified TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    resolved_at TIMESTAMP WITH TIME ZONE
);

-- Compliance assessments
CREATE TABLE compliance_assessments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id),
    framework VARCHAR(50) NOT NULL,
    assessment_date TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    overall_score DECIMAL(5,2),
    status VARCHAR(20) DEFAULT 'in_progress',
    findings JSONB,
    recommendations JSONB,
    next_assessment_due TIMESTAMP WITH TIME ZONE,
    created_by UUID REFERENCES users(id)
);

-- Security incidents
CREATE TABLE security_incidents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(20) DEFAULT 'open',
    asset_id UUID REFERENCES network_assets(id),
    vulnerability_id UUID REFERENCES vulnerabilities(id),
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    resolved_at TIMESTAMP WITH TIME ZONE,
    assigned_to UUID REFERENCES users(id),
    resolution_notes TEXT
);

-- Scheduled scans
CREATE TABLE scheduled_scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id),
    name VARCHAR(255) NOT NULL,
    scan_type VARCHAR(50) NOT NULL,
    target_network CIDR,
    frequency VARCHAR(20) NOT NULL,
    next_run TIMESTAMP WITH TIME ZONE NOT NULL,
    last_run TIMESTAMP WITH TIME ZONE,
    configuration JSONB,
    is_active BOOLEAN DEFAULT TRUE,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Automated reports
CREATE TABLE automated_reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id),
    name VARCHAR(255) NOT NULL,
    report_type VARCHAR(50) NOT NULL,
    format VARCHAR(20) NOT NULL,
    frequency VARCHAR(20) NOT NULL,
    recipients TEXT[],
    template JSONB,
    last_generated TIMESTAMP WITH TIME ZONE,
    next_generation TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- System configuration
CREATE TABLE system_configuration (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id),
    category VARCHAR(50) NOT NULL,
    key VARCHAR(100) NOT NULL,
    value JSONB,
    description TEXT,
    updated_by UUID REFERENCES users(id),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(organization_id, category, key)
);

-- Audit logs
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id),
    user_id UUID REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id UUID,
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for performance
CREATE INDEX idx_network_assets_ip ON network_assets(ip_address);
CREATE INDEX idx_network_assets_org ON network_assets(organization_id);
CREATE INDEX idx_scan_sessions_org_date ON scan_sessions(organization_id, start_time);
CREATE INDEX idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX idx_vulnerabilities_status ON vulnerabilities(status);
CREATE INDEX idx_port_scans_port ON port_scans(port_number);
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX idx_scheduled_scans_next_run ON scheduled_scans(next_run) WHERE is_active = TRUE;

-- Create views for common queries
CREATE VIEW active_vulnerabilities AS
SELECT 
    v.*,
    na.hostname,
    na.asset_type,
    na.criticality_level
FROM vulnerabilities v
JOIN network_assets na ON v.asset_id = na.id
WHERE v.status = 'open';

CREATE VIEW network_summary AS
SELECT 
    organization_id,
    COUNT(*) as total_assets,
    COUNT(*) FILTER (WHERE is_active = TRUE) as active_assets,
    COUNT(*) FILTER (WHERE criticality_level = 'high') as critical_assets,
    COUNT(*) FILTER (WHERE criticality_level = 'medium') as medium_assets,
    COUNT(*) FILTER (WHERE criticality_level = 'low') as low_assets
FROM network_assets
GROUP BY organization_id;

-- Insert default organization and admin user
INSERT INTO organizations (name, domain) VALUES ('Default Organization', 'localhost');

INSERT INTO users (organization_id, username, email, password_hash, first_name, last_name, role) 
VALUES (
    (SELECT id FROM organizations WHERE name = 'Default Organization'),
    'admin',
    'admin@localhost',
    crypt('admin123', gen_salt('bf')),
    'System',
    'Administrator',
    'admin'
);

-- Insert default system configuration
INSERT INTO system_configuration (organization_id, category, key, value, description)
VALUES 
(
    (SELECT id FROM organizations WHERE name = 'Default Organization'),
    'scanning',
    'default_timeout',
    '30',
    'Default scan timeout in seconds'
),
(
    (SELECT id FROM organizations WHERE name = 'Default Organization'),
    'scanning',
    'max_concurrent_scans',
    '100',
    'Maximum number of concurrent scan operations'
),
(
    (SELECT id FROM organizations WHERE name = 'Default Organization'),
    'notifications',
    'smtp_enabled',
    'false',
    'Enable SMTP notifications'
);

-- Commit the transaction
COMMIT;