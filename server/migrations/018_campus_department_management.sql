-- ============================================================================
-- Migration 018: Campus & Department Management (Module 4)
-- Multi-institution organizational hierarchy with full lifecycle, approval
-- workflows, tenant isolation, and audit trail.
-- ============================================================================

-- 1. Campus approvals / lifecycle state transitions
CREATE TABLE IF NOT EXISTS campus_approvals (
    id VARCHAR(64) PRIMARY KEY,
    campus_id VARCHAR(64) NOT NULL,
    institution_id VARCHAR(64) NOT NULL,
    action VARCHAR(40) NOT NULL,          -- create, activate, suspend, close, transfer, archive
    requested_by VARCHAR(64) NOT NULL,
    requested_at BIGINT NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending', -- pending, approved, rejected, cancelled
    decided_by VARCHAR(64),
    decided_at BIGINT,
    reason TEXT,
    decision_reason TEXT,
    approved_config JSONB DEFAULT '{}'::jsonb,
    CONSTRAINT fk_campus_approval_campus FOREIGN KEY (campus_id) REFERENCES campuses(id),
    CONSTRAINT fk_campus_approval_inst FOREIGN KEY (institution_id) REFERENCES tenants(id),
    CONSTRAINT fk_campus_approval_requester FOREIGN KEY (requested_by) REFERENCES users(id),
    CONSTRAINT fk_campus_approval_decider FOREIGN KEY (decided_by) REFERENCES users(id)
);

-- 2. Department approvals / lifecycle state transitions
CREATE TABLE IF NOT EXISTS department_approvals (
    id VARCHAR(64) PRIMARY KEY,
    department_id VARCHAR(64) NOT NULL,
    institution_id VARCHAR(64) NOT NULL,
    campus_id VARCHAR(64) NOT NULL,
    action VARCHAR(40) NOT NULL,          -- create, activate, suspend, archive, transfer
    requested_by VARCHAR(64) NOT NULL,
    requested_at BIGINT NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    decided_by VARCHAR(64),
    decided_at BIGINT,
    reason TEXT,
    decision_reason TEXT,
    approved_config JSONB DEFAULT '{}'::jsonb,
    CONSTRAINT fk_dept_approval_dept FOREIGN KEY (department_id) REFERENCES departments(id),
    CONSTRAINT fk_dept_approval_inst FOREIGN KEY (institution_id) REFERENCES tenants(id),
    CONSTRAINT fk_dept_approval_campus FOREIGN KEY (campus_id) REFERENCES campuses(id),
    CONSTRAINT fk_dept_approval_requester FOREIGN KEY (requested_by) REFERENCES users(id),
    CONSTRAINT fk_dept_approval_decider FOREIGN KEY (decided_by) REFERENCES users(id)
);

-- 3. Campus user assignments (scoped RBAC)
CREATE TABLE IF NOT EXISTS campus_user_assignments (
    id VARCHAR(64) PRIMARY KEY,
    campus_id VARCHAR(64) NOT NULL,
    institution_id VARCHAR(64) NOT NULL,
    user_id VARCHAR(64) NOT NULL,
    role VARCHAR(40) NOT NULL DEFAULT 'campus_admin', -- campus_admin, campus_staff, campus_invigilator
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    assigned_by VARCHAR(64),
    assigned_at BIGINT NOT NULL,
    expires_at BIGINT,
    reason TEXT,
    CONSTRAINT fk_cua_campus FOREIGN KEY (campus_id) REFERENCES campuses(id),
    CONSTRAINT fk_cua_inst FOREIGN KEY (institution_id) REFERENCES tenants(id),
    CONSTRAINT fk_cua_user FOREIGN KEY (user_id) REFERENCES users(id),
    CONSTRAINT fk_cua_assigner FOREIGN KEY (assigned_by) REFERENCES users(id),
    CONSTRAINT uq_campus_user_role UNIQUE (campus_id, user_id, role)
);

-- 4. Department user assignments (scoped RBAC)
CREATE TABLE IF NOT EXISTS department_user_assignments (
    id VARCHAR(64) PRIMARY KEY,
    department_id VARCHAR(64) NOT NULL,
    institution_id VARCHAR(64) NOT NULL,
    campus_id VARCHAR(64) NOT NULL,
    user_id VARCHAR(64) NOT NULL,
    role VARCHAR(40) NOT NULL DEFAULT 'department_admin', -- department_admin, department_head, department_staff
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    assigned_by VARCHAR(64),
    assigned_at BIGINT NOT NULL,
    expires_at BIGINT,
    reason TEXT,
    CONSTRAINT fk_dua_dept FOREIGN KEY (department_id) REFERENCES departments(id),
    CONSTRAINT fk_dua_inst FOREIGN KEY (institution_id) REFERENCES tenants(id),
    CONSTRAINT fk_dua_campus FOREIGN KEY (campus_id) REFERENCES campuses(id),
    CONSTRAINT fk_dua_user FOREIGN KEY (user_id) REFERENCES users(id),
    CONSTRAINT fk_dua_assigner FOREIGN KEY (assigned_by) REFERENCES users(id),
    CONSTRAINT uq_dept_user_role UNIQUE (department_id, user_id, role)
);

-- 5. Academic programs offered by departments
CREATE TABLE IF NOT EXISTS academic_programs (
    id VARCHAR(64) PRIMARY KEY,
    department_id VARCHAR(64) NOT NULL,
    institution_id VARCHAR(64) NOT NULL,
    campus_id VARCHAR(64) NOT NULL,
    program_code VARCHAR(32) NOT NULL,
    program_name VARCHAR(128) NOT NULL,
    program_type VARCHAR(40) DEFAULT 'academic', -- academic, research, professional, vocational
    degree_level VARCHAR(40), -- undergraduate, graduate, doctoral, diploma, certificate
    duration_months INTEGER,
    total_seats INTEGER DEFAULT 0,
    status VARCHAR(20) NOT NULL DEFAULT 'draft', -- draft, pending, active, suspended, archived
    created_by VARCHAR(64),
    created_at BIGINT NOT NULL,
    updated_at BIGINT,
    updated_by VARCHAR(64),
    CONSTRAINT fk_prog_dept FOREIGN KEY (department_id) REFERENCES departments(id),
    CONSTRAINT fk_prog_inst FOREIGN KEY (institution_id) REFERENCES tenants(id),
    CONSTRAINT fk_prog_campus FOREIGN KEY (campus_id) REFERENCES campuses(id),
    CONSTRAINT uq_prog_code UNIQUE (institution_id, program_code)
);

-- 6. Campus capacity allocations (exam rooms, devices)
CREATE TABLE IF NOT EXISTS campus_capacity_allocations (
    id VARCHAR(64) PRIMARY KEY,
    campus_id VARCHAR(64) NOT NULL,
    institution_id VARCHAR(64) NOT NULL,
    allocation_type VARCHAR(40) NOT NULL, -- exam_room, computer_lab, device_pool, usb_storage
    name VARCHAR(128) NOT NULL,
    total_capacity INTEGER NOT NULL DEFAULT 0,
    available_capacity INTEGER NOT NULL DEFAULT 0,
    reserved_capacity INTEGER NOT NULL DEFAULT 0,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    created_by VARCHAR(64),
    created_at BIGINT NOT NULL,
    updated_at BIGINT,
    CONSTRAINT fk_cca_campus FOREIGN KEY (campus_id) REFERENCES campuses(id),
    CONSTRAINT fk_cca_inst FOREIGN KEY (institution_id) REFERENCES tenants(id)
);

-- 7. Campus OS & policy deployment references
CREATE TABLE IF NOT EXISTS campus_os_policies (
    id VARCHAR(64) PRIMARY KEY,
    campus_id VARCHAR(64) NOT NULL,
    institution_id VARCHAR(64) NOT NULL,
    release_id VARCHAR(64),                    -- links to releases table
    release_version VARCHAR(32),
    policy_id VARCHAR(64),                     -- links to policies table
    policy_version INTEGER,
    device_group VARCHAR(64),
    status VARCHAR(20) NOT NULL DEFAULT 'draft', -- draft, pending, approved, deployed, revoked
    deployed_by VARCHAR(64),
    deployed_at BIGINT,
    approved_by VARCHAR(64),
    approved_at BIGINT,
    created_by VARCHAR(64),
    created_at BIGINT NOT NULL,
    CONSTRAINT fk_cop_campus FOREIGN KEY (campus_id) REFERENCES campuses(id),
    CONSTRAINT fk_cop_inst FOREIGN KEY (institution_id) REFERENCES tenants(id),
    CONSTRAINT fk_cop_release FOREIGN KEY (release_id) REFERENCES releases(id),
    CONSTRAINT fk_cop_policy FOREIGN KEY (policy_id) REFERENCES policies(id),
    CONSTRAINT fk_cop_deployer FOREIGN KEY (deployed_by) REFERENCES users(id),
    CONSTRAINT fk_cop_approver FOREIGN KEY (approved_by) REFERENCES users(id)
);

-- 8. Device assignments to organizational scopes
CREATE TABLE IF NOT EXISTS device_assignments (
    id VARCHAR(64) PRIMARY KEY,
    device_id VARCHAR(64) NOT NULL,
    institution_id VARCHAR(64) NOT NULL,
    campus_id VARCHAR(64),
    department_id VARCHAR(64),
    assigned_by VARCHAR(64),
    assigned_at BIGINT NOT NULL,
    returned_at BIGINT,
    status VARCHAR(20) NOT NULL DEFAULT 'active', -- active, returned, transferred
    reason TEXT,
    CONSTRAINT fk_da_device FOREIGN KEY (device_id) REFERENCES devices(id),
    CONSTRAINT fk_da_inst FOREIGN KEY (institution_id) REFERENCES tenants(id),
    CONSTRAINT fk_da_campus FOREIGN KEY (campus_id) REFERENCES campuses(id),
    CONSTRAINT fk_da_dept FOREIGN KEY (department_id) REFERENCES departments(id),
    CONSTRAINT fk_da_assigner FOREIGN KEY (assigned_by) REFERENCES users(id)
);

-- 9. Organization change history (immutable audit trail)
CREATE TABLE IF NOT EXISTS organization_change_history (
    id VARCHAR(64) PRIMARY KEY,
    institution_id VARCHAR(64) NOT NULL,
    campus_id VARCHAR(64),
    department_id VARCHAR(64),
    actor_id VARCHAR(64) NOT NULL,
    action VARCHAR(64) NOT NULL,           -- campus_create, campus_activate, dept_transfer, etc.
    target_table VARCHAR(40) NOT NULL,
    target_id VARCHAR(64) NOT NULL,
    previous_values JSONB,
    new_values JSONB,
    reason TEXT,
    created_at BIGINT NOT NULL,
    CONSTRAINT fk_och_inst FOREIGN KEY (institution_id) REFERENCES tenants(id),
    CONSTRAINT fk_och_actor FOREIGN KEY (actor_id) REFERENCES users(id)
);

-- Indexes for performance and tenant-scoped queries
CREATE INDEX IF NOT EXISTS idx_campus_approvals_inst ON campus_approvals(institution_id, status);
CREATE INDEX IF NOT EXISTS idx_campus_approvals_campus ON campus_approvals(campus_id);
CREATE INDEX IF NOT EXISTS idx_dept_approvals_inst ON department_approvals(institution_id, status);
CREATE INDEX IF NOT EXISTS idx_dept_approvals_dept ON department_approvals(department_id);
CREATE INDEX IF NOT EXISTS idx_campus_user_assignments_inst ON campus_user_assignments(institution_id, user_id, status);
CREATE INDEX IF NOT EXISTS idx_campus_user_assignments_campus ON campus_user_assignments(campus_id, status);
CREATE INDEX IF NOT EXISTS idx_dept_user_assignments_inst ON department_user_assignments(institution_id, user_id, status);
CREATE INDEX IF NOT EXISTS idx_dept_user_assignments_dept ON department_user_assignments(department_id, status);
CREATE INDEX IF NOT EXISTS idx_academic_programs_dept ON academic_programs(department_id, status);
CREATE INDEX IF NOT EXISTS idx_academic_programs_inst ON academic_programs(institution_id, status);
CREATE INDEX IF NOT EXISTS idx_campus_capacity_inst ON campus_capacity_allocations(institution_id, status);
CREATE INDEX IF NOT EXISTS idx_campus_os_policies_inst ON campus_os_policies(institution_id, status);
CREATE INDEX IF NOT EXISTS idx_device_assignments_inst ON device_assignments(institution_id, status);
CREATE INDEX IF NOT EXISTS idx_device_assignments_device ON device_assignments(device_id);
CREATE INDEX IF NOT EXISTS idx_org_change_inst ON organization_change_history(institution_id, created_at);
CREATE INDEX IF NOT EXISTS idx_org_change_actor ON organization_change_history(actor_id, created_at);

-- Update campuses table: add approval_status and deployment fields if not exist
-- (PostgreSQL does not support ADD COLUMN IF NOT EXISTS directly in all versions;
-- we guard with DO blocks)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='campuses' AND column_name='approval_status') THEN
        ALTER TABLE campuses ADD COLUMN approval_status VARCHAR(20) DEFAULT 'pending';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='campuses' AND column_name='approved_by') THEN
        ALTER TABLE campuses ADD COLUMN approved_by VARCHAR(64);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='campuses' AND column_name='approved_at') THEN
        ALTER TABLE campuses ADD COLUMN approved_at BIGINT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='campuses' AND column_name='deployment_status') THEN
        ALTER TABLE campuses ADD COLUMN deployment_status VARCHAR(20) DEFAULT 'not_deployed';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='campuses' AND column_name='last_deployed_at') THEN
        ALTER TABLE campuses ADD COLUMN last_deployed_at BIGINT;
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='departments' AND column_name='approval_status') THEN
        ALTER TABLE departments ADD COLUMN approval_status VARCHAR(20) DEFAULT 'pending';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='departments' AND column_name='approved_by') THEN
        ALTER TABLE departments ADD COLUMN approved_by VARCHAR(64);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='departments' AND column_name='approved_at') THEN
        ALTER TABLE departments ADD COLUMN approved_at BIGINT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='departments' AND column_name='department_head_id') THEN
        ALTER TABLE departments ADD COLUMN department_head_id VARCHAR(64);
    END IF;
END $$;

-- Record migration
INSERT INTO examos_schema_migrations (version, applied_at)
VALUES ('018', EXTRACT(EPOCH FROM NOW()) * 1000)
ON CONFLICT (version) DO NOTHING;
