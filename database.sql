-- SafeVault Database Schema
-- This script creates the database structure for the SafeVault application

-- Create database
CREATE DATABASE IF NOT EXISTS SafeVault;
USE SafeVault;

-- Create Users table with secure design
CREATE TABLE Users (
    UserID INT PRIMARY KEY AUTO_INCREMENT,
    Username VARCHAR(100) NOT NULL UNIQUE,
    Email VARCHAR(100) NOT NULL UNIQUE,
    PasswordHash VARCHAR(255) NOT NULL,
    Salt VARCHAR(255) NOT NULL,
    CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UpdatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    IsActive BOOLEAN DEFAULT TRUE,
    LastLogin TIMESTAMP NULL,
    FailedLoginAttempts INT DEFAULT 0,
    AccountLockedUntil TIMESTAMP NULL
);

-- Create audit log table for security monitoring
CREATE TABLE AuditLog (
    LogID INT PRIMARY KEY AUTO_INCREMENT,
    UserID INT,
    Action VARCHAR(100) NOT NULL,
    Details TEXT,
    IPAddress VARCHAR(45),
    UserAgent TEXT,
    Timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (UserID) REFERENCES Users(UserID) ON DELETE SET NULL
);

-- Create session table for secure session management
CREATE TABLE UserSessions (
    SessionID VARCHAR(255) PRIMARY KEY,
    UserID INT NOT NULL,
    CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ExpiresAt TIMESTAMP NOT NULL,
    IPAddress VARCHAR(45),
    UserAgent TEXT,
    IsActive BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (UserID) REFERENCES Users(UserID) ON DELETE CASCADE
);

-- Create roles table
CREATE TABLE Roles (
    RoleID INT PRIMARY KEY AUTO_INCREMENT,
    RoleName VARCHAR(50) NOT NULL UNIQUE,
    Description TEXT,
    IsActive BOOLEAN DEFAULT TRUE,
    CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create permissions table
CREATE TABLE Permissions (
    PermissionID INT PRIMARY KEY AUTO_INCREMENT,
    Action VARCHAR(100) NOT NULL,
    Resource VARCHAR(100),
    Description TEXT,
    CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY unique_action_resource (Action, Resource)
);

-- Create role permissions junction table
CREATE TABLE RolePermissions (
    RoleID INT NOT NULL,
    PermissionID INT NOT NULL,
    CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (RoleID, PermissionID),
    FOREIGN KEY (RoleID) REFERENCES Roles(RoleID) ON DELETE CASCADE,
    FOREIGN KEY (PermissionID) REFERENCES Permissions(PermissionID) ON DELETE CASCADE
);

-- Create user roles junction table
CREATE TABLE UserRoles (
    UserID INT NOT NULL,
    RoleID INT NOT NULL,
    AssignedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    AssignedBy INT,
    PRIMARY KEY (UserID, RoleID),
    FOREIGN KEY (UserID) REFERENCES Users(UserID) ON DELETE CASCADE,
    FOREIGN KEY (RoleID) REFERENCES Roles(RoleID) ON DELETE CASCADE,
    FOREIGN KEY (AssignedBy) REFERENCES Users(UserID) ON DELETE SET NULL
);

-- Create indexes for performance and security
CREATE INDEX idx_users_username ON Users(Username);
CREATE INDEX idx_users_email ON Users(Email);
CREATE INDEX idx_audit_user_timestamp ON AuditLog(UserID, Timestamp);
CREATE INDEX idx_sessions_user_expires ON UserSessions(UserID, ExpiresAt);

-- Insert sample data for testing (with secure password hashing)
-- Note: In production, passwords should be hashed using bcrypt or similar
INSERT INTO Users (Username, Email, PasswordHash, Salt) VALUES 
('admin', 'admin@safevault.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/8KzKz2K', 'randomsalt1'),
('testuser', 'test@safevault.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/8KzKz2K', 'randomsalt2');

-- Insert default roles
INSERT INTO Roles (RoleName, Description) VALUES 
('Admin', 'System administrator with full access'),
('User', 'Regular user with basic access'),
('Manager', 'Manager with elevated permissions'),
('Auditor', 'Auditor with read-only access');

-- Insert default permissions
INSERT INTO Permissions (Action, Resource, Description) VALUES 
('CreateUser', 'Users', 'Create new users'),
('ReadUser', 'Users', 'View user information'),
('UpdateUser', 'Users', 'Update user information'),
('DeleteUser', 'Users', 'Delete users'),
('AssignRole', 'Roles', 'Assign roles to users'),
('RemoveRole', 'Roles', 'Remove roles from users'),
('ReadAuditLog', 'AuditLog', 'View audit logs'),
('ManageRoles', 'Roles', 'Manage roles and permissions'),
('AccessAdminPanel', 'AdminPanel', 'Access administrative panel'),
('ViewReports', 'Reports', 'View system reports'),
('ManageSettings', 'Settings', 'Manage system settings');

-- Assign permissions to roles
-- Admin role gets all permissions
INSERT INTO RolePermissions (RoleID, PermissionID) 
SELECT r.RoleID, p.PermissionID 
FROM Roles r, Permissions p 
WHERE r.RoleName = 'Admin';

-- User role gets basic permissions
INSERT INTO RolePermissions (RoleID, PermissionID) 
SELECT r.RoleID, p.PermissionID 
FROM Roles r, Permissions p 
WHERE r.RoleName = 'User' 
AND p.Action IN ('ReadUser', 'ViewReports');

-- Manager role gets elevated permissions
INSERT INTO RolePermissions (RoleID, PermissionID) 
SELECT r.RoleID, p.PermissionID 
FROM Roles r, Permissions p 
WHERE r.RoleName = 'Manager' 
AND p.Action IN ('CreateUser', 'ReadUser', 'UpdateUser', 'AssignRole', 'ReadAuditLog', 'ViewReports');

-- Auditor role gets read-only permissions
INSERT INTO RolePermissions (RoleID, PermissionID) 
SELECT r.RoleID, p.PermissionID 
FROM Roles r, Permissions p 
WHERE r.RoleName = 'Auditor' 
AND p.Action IN ('ReadUser', 'ReadAuditLog', 'ViewReports');

-- Assign roles to sample users
INSERT INTO UserRoles (UserID, RoleID) 
SELECT u.UserID, r.RoleID 
FROM Users u, Roles r 
WHERE u.Username = 'admin' AND r.RoleName = 'Admin';

INSERT INTO UserRoles (UserID, RoleID) 
SELECT u.UserID, r.RoleID 
FROM Users u, Roles r 
WHERE u.Username = 'testuser' AND r.RoleName = 'User';

-- Create stored procedures for secure operations
DELIMITER //

-- Secure user creation procedure
CREATE PROCEDURE CreateUser(
    IN p_username VARCHAR(100),
    IN p_email VARCHAR(100),
    IN p_password_hash VARCHAR(255),
    IN p_salt VARCHAR(255),
    IN p_ip_address VARCHAR(45),
    IN p_user_agent TEXT
)
BEGIN
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        ROLLBACK;
        RESIGNAL;
    END;
    
    START TRANSACTION;
    
    -- Insert user
    INSERT INTO Users (Username, Email, PasswordHash, Salt) 
    VALUES (p_username, p_email, p_password_hash, p_salt);
    
    -- Log the action
    INSERT INTO AuditLog (UserID, Action, Details, IPAddress, UserAgent)
    VALUES (LAST_INSERT_ID(), 'USER_CREATED', CONCAT('User created: ', p_username), p_ip_address, p_user_agent);
    
    COMMIT;
END //

-- Secure user authentication procedure
CREATE PROCEDURE AuthenticateUser(
    IN p_username VARCHAR(100),
    IN p_password_hash VARCHAR(255),
    IN p_ip_address VARCHAR(45),
    IN p_user_agent TEXT,
    OUT p_user_id INT,
    OUT p_success BOOLEAN
)
BEGIN
    DECLARE user_exists INT DEFAULT 0;
    DECLARE account_locked BOOLEAN DEFAULT FALSE;
    DECLARE failed_attempts INT DEFAULT 0;
    
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        ROLLBACK;
        RESIGNAL;
    END;
    
    START TRANSACTION;
    
    -- Check if user exists and get account status
    SELECT UserID, 
           CASE WHEN AccountLockedUntil > NOW() THEN TRUE ELSE FALSE END,
           FailedLoginAttempts
    INTO p_user_id, account_locked, failed_attempts
    FROM Users 
    WHERE Username = p_username AND IsActive = TRUE;
    
    IF p_user_id IS NULL THEN
        SET p_success = FALSE;
        -- Log failed attempt
        INSERT INTO AuditLog (Action, Details, IPAddress, UserAgent)
        VALUES ('LOGIN_FAILED', CONCAT('Invalid username: ', p_username), p_ip_address, p_user_agent);
    ELSEIF account_locked THEN
        SET p_success = FALSE;
        -- Log locked account attempt
        INSERT INTO AuditLog (UserID, Action, Details, IPAddress, UserAgent)
        VALUES (p_user_id, 'LOGIN_BLOCKED', 'Account is locked', p_ip_address, p_user_agent);
    ELSE
        -- Verify password
        SELECT COUNT(*) INTO user_exists
        FROM Users 
        WHERE UserID = p_user_id AND PasswordHash = p_password_hash;
        
        IF user_exists > 0 THEN
            SET p_success = TRUE;
            -- Reset failed attempts and update last login
            UPDATE Users 
            SET FailedLoginAttempts = 0, 
                LastLogin = NOW(),
                AccountLockedUntil = NULL
            WHERE UserID = p_user_id;
            
            -- Log successful login
            INSERT INTO AuditLog (UserID, Action, Details, IPAddress, UserAgent)
            VALUES (p_user_id, 'LOGIN_SUCCESS', 'User logged in successfully', p_ip_address, p_user_agent);
        ELSE
            SET p_success = FALSE;
            -- Increment failed attempts
            UPDATE Users 
            SET FailedLoginAttempts = FailedLoginAttempts + 1,
                AccountLockedUntil = CASE 
                    WHEN FailedLoginAttempts >= 4 THEN DATE_ADD(NOW(), INTERVAL 30 MINUTE)
                    ELSE AccountLockedUntil
                END
            WHERE UserID = p_user_id;
            
            -- Log failed attempt
            INSERT INTO AuditLog (UserID, Action, Details, IPAddress, UserAgent)
            VALUES (p_user_id, 'LOGIN_FAILED', 'Invalid password', p_ip_address, p_user_agent);
        END IF;
    END IF;
    
    COMMIT;
END //

DELIMITER ;
