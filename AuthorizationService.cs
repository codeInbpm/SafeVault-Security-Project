using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using SafeVault.Data;
using SafeVault.Services;

namespace SafeVault.Services
{
    /// <summary>
    /// Role-based authorization service (RBAC)
    /// </summary>
    public class AuthorizationService
    {
        private readonly SecureDatabaseManager _dbManager;
        private readonly SessionManager _sessionManager;
        private readonly AuditLogger _auditLogger;

        public AuthorizationService(SecureDatabaseManager dbManager, SessionManager sessionManager, AuditLogger auditLogger)
        {
            _dbManager = dbManager ?? throw new ArgumentNullException(nameof(dbManager));
            _sessionManager = sessionManager ?? throw new ArgumentNullException(nameof(sessionManager));
            _auditLogger = auditLogger ?? throw new ArgumentNullException(nameof(auditLogger));
        }

        /// <summary>
        /// Checks if a user has a specific role
        /// </summary>
        /// <param name="userId">User ID</param>
        /// <param name="roleName">Role name</param>
        /// <returns>True if user has the role</returns>
        public async Task<bool> UserHasRoleAsync(int userId, string roleName)
        {
            try
            {
                if (userId <= 0 || string.IsNullOrWhiteSpace(roleName))
                    return false;

                var userRoles = await _dbManager.GetUserRolesAsync(userId);
                return userRoles.Any(role => role.Equals(roleName, StringComparison.OrdinalIgnoreCase));
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Checks if a user has any of the specified roles
        /// </summary>
        /// <param name="userId">User ID</param>
        /// <param name="roleNames">Role names</param>
        /// <returns>True if user has any of the roles</returns>
        public async Task<bool> UserHasAnyRoleAsync(int userId, params string[] roleNames)
        {
            try
            {
                if (userId <= 0 || roleNames == null || roleNames.Length == 0)
                    return false;

                var userRoles = await _dbManager.GetUserRolesAsync(userId);
                return roleNames.Any(roleName => userRoles.Any(role => role.Equals(roleName, StringComparison.OrdinalIgnoreCase)));
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Checks if a user has all of the specified roles
        /// </summary>
        /// <param name="userId">User ID</param>
        /// <param name="roleNames">Role names</param>
        /// <returns>True if user has all of the roles</returns>
        public async Task<bool> UserHasAllRolesAsync(int userId, params string[] roleNames)
        {
            try
            {
                if (userId <= 0 || roleNames == null || roleNames.Length == 0)
                    return false;

                var userRoles = await _dbManager.GetUserRolesAsync(userId);
                return roleNames.All(roleName => userRoles.Any(role => role.Equals(roleName, StringComparison.OrdinalIgnoreCase)));
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Checks if a user can perform a specific action
        /// </summary>
        /// <param name="userId">User ID</param>
        /// <param name="action">Action name</param>
        /// <param name="resource">Resource name (optional)</param>
        /// <returns>True if user can perform the action</returns>
        public async Task<bool> UserCanPerformActionAsync(int userId, string action, string resource = null)
        {
            try
            {
                if (userId <= 0 || string.IsNullOrWhiteSpace(action))
                    return false;

                var userRoles = await _dbManager.GetUserRolesAsync(userId);
                var permissions = await _dbManager.GetRolePermissionsAsync(userRoles.ToArray());

                return permissions.Any(permission => 
                    permission.Action.Equals(action, StringComparison.OrdinalIgnoreCase) &&
                    (string.IsNullOrWhiteSpace(resource) || permission.Resource == null || 
                     permission.Resource.Equals(resource, StringComparison.OrdinalIgnoreCase)));
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Authorizes a user for a specific action and logs the attempt
        /// </summary>
        /// <param name="userId">User ID</param>
        /// <param name="action">Action name</param>
        /// <param name="resource">Resource name (optional)</param>
        /// <param name="ipAddress">Client IP address</param>
        /// <param name="userAgent">Client user agent</param>
        /// <returns>Authorization result</returns>
        public async Task<AuthorizationResult> AuthorizeUserAsync(int userId, string action, string resource, string ipAddress, string userAgent)
        {
            try
            {
                if (userId <= 0 || string.IsNullOrWhiteSpace(action))
                {
                    await _auditLogger.LogAsync(userId, "AUTHORIZATION_FAILED", $"Invalid parameters: userId={userId}, action={action}", ipAddress, userAgent);
                    return new AuthorizationResult
                    {
                        IsAuthorized = false,
                        ErrorMessage = "Invalid authorization parameters"
                    };
                }

                bool isAuthorized = await UserCanPerformActionAsync(userId, action, resource);
                
                if (isAuthorized)
                {
                    await _auditLogger.LogAsync(userId, "AUTHORIZATION_SUCCESS", $"Authorized for action: {action}, resource: {resource}", ipAddress, userAgent);
                    return new AuthorizationResult
                    {
                        IsAuthorized = true,
                        Message = "Access granted"
                    };
                }
                else
                {
                    await _auditLogger.LogAsync(userId, "AUTHORIZATION_DENIED", $"Denied access to action: {action}, resource: {resource}", ipAddress, userAgent);
                    return new AuthorizationResult
                    {
                        IsAuthorized = false,
                        ErrorMessage = "Access denied"
                    };
                }
            }
            catch (Exception ex)
            {
                await _auditLogger.LogAsync(userId, "AUTHORIZATION_ERROR", $"Authorization error: {ex.Message}", ipAddress, userAgent);
                return new AuthorizationResult
                {
                    IsAuthorized = false,
                    ErrorMessage = "An error occurred during authorization"
                };
            }
        }

        /// <summary>
        /// Validates a session and checks authorization
        /// </summary>
        /// <param name="token">JWT-like token</param>
        /// <param name="action">Required action</param>
        /// <param name="resource">Resource name (optional)</param>
        /// <param name="ipAddress">Client IP address</param>
        /// <param name="userAgent">Client user agent</param>
        /// <returns>Authorization result with user information</returns>
        public async Task<SessionAuthorizationResult> AuthorizeSessionAsync(string token, string action, string resource, string ipAddress, string userAgent)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(token))
                {
                    await _auditLogger.LogAsync(null, "AUTHORIZATION_FAILED", "Empty token", ipAddress, userAgent);
                    return new SessionAuthorizationResult
                    {
                        IsAuthorized = false,
                        ErrorMessage = "Token is required"
                    };
                }

                // Validate session
                var session = await _sessionManager.ValidateTokenAsync(token);
                if (session == null)
                {
                    await _auditLogger.LogAsync(null, "AUTHORIZATION_FAILED", "Invalid or expired token", ipAddress, userAgent);
                    return new SessionAuthorizationResult
                    {
                        IsAuthorized = false,
                        ErrorMessage = "Invalid or expired session"
                    };
                }

                // Check authorization
                var authResult = await AuthorizeUserAsync(session.UserId, action, resource, ipAddress, userAgent);
                
                if (authResult.IsAuthorized)
                {
                    // Get user information
                    var user = await _dbManager.GetUserByIdAsync(session.UserId);
                    var userRoles = await _dbManager.GetUserRolesAsync(session.UserId);

                    return new SessionAuthorizationResult
                    {
                        IsAuthorized = true,
                        UserId = session.UserId,
                        Username = user?.Username,
                        Email = user?.Email,
                        Roles = userRoles.ToList(),
                        SessionId = session.SessionId,
                        Message = "Access granted"
                    };
                }
                else
                {
                    return new SessionAuthorizationResult
                    {
                        IsAuthorized = false,
                        UserId = session.UserId,
                        ErrorMessage = authResult.ErrorMessage
                    };
                }
            }
            catch (Exception ex)
            {
                await _auditLogger.LogAsync(null, "AUTHORIZATION_ERROR", $"Session authorization error: {ex.Message}", ipAddress, userAgent);
                return new SessionAuthorizationResult
                {
                    IsAuthorized = false,
                    ErrorMessage = "An error occurred during authorization"
                };
            }
        }

        /// <summary>
        /// Assigns a role to a user
        /// </summary>
        /// <param name="userId">User ID</param>
        /// <param name="roleName">Role name</param>
        /// <param name="assignedBy">User ID who assigned the role</param>
        /// <param name="ipAddress">Client IP address</param>
        /// <param name="userAgent">Client user agent</param>
        /// <returns>Assignment result</returns>
        public async Task<RoleAssignmentResult> AssignRoleToUserAsync(int userId, string roleName, int assignedBy, string ipAddress, string userAgent)
        {
            try
            {
                if (userId <= 0 || string.IsNullOrWhiteSpace(roleName) || assignedBy <= 0)
                {
                    await _auditLogger.LogAsync(assignedBy, "ROLE_ASSIGNMENT_FAILED", $"Invalid parameters: userId={userId}, role={roleName}", ipAddress, userAgent);
                    return new RoleAssignmentResult
                    {
                        IsSuccess = false,
                        ErrorMessage = "Invalid parameters"
                    };
                }

                // Check if the assigner has permission to assign roles
                bool canAssignRoles = await UserCanPerformActionAsync(assignedBy, "AssignRole");
                if (!canAssignRoles)
                {
                    await _auditLogger.LogAsync(assignedBy, "ROLE_ASSIGNMENT_DENIED", $"User {assignedBy} attempted to assign role {roleName} to user {userId}", ipAddress, userAgent);
                    return new RoleAssignmentResult
                    {
                        IsSuccess = false,
                        ErrorMessage = "Insufficient permissions to assign roles"
                    };
                }

                // Check if role exists
                bool roleExists = await _dbManager.RoleExistsAsync(roleName);
                if (!roleExists)
                {
                    await _auditLogger.LogAsync(assignedBy, "ROLE_ASSIGNMENT_FAILED", $"Role does not exist: {roleName}", ipAddress, userAgent);
                    return new RoleAssignmentResult
                    {
                        IsSuccess = false,
                        ErrorMessage = "Role does not exist"
                    };
                }

                // Check if user exists
                var user = await _dbManager.GetUserByIdAsync(userId);
                if (user == null)
                {
                    await _auditLogger.LogAsync(assignedBy, "ROLE_ASSIGNMENT_FAILED", $"User does not exist: {userId}", ipAddress, userAgent);
                    return new RoleAssignmentResult
                    {
                        IsSuccess = false,
                        ErrorMessage = "User does not exist"
                    };
                }

                // Check if user already has the role
                bool hasRole = await UserHasRoleAsync(userId, roleName);
                if (hasRole)
                {
                    await _auditLogger.LogAsync(assignedBy, "ROLE_ASSIGNMENT_FAILED", $"User {userId} already has role {roleName}", ipAddress, userAgent);
                    return new RoleAssignmentResult
                    {
                        IsSuccess = false,
                        ErrorMessage = "User already has this role"
                    };
                }

                // Assign the role
                await _dbManager.AssignRoleToUserAsync(userId, roleName);

                await _auditLogger.LogAsync(assignedBy, "ROLE_ASSIGNMENT_SUCCESS", $"Assigned role {roleName} to user {userId}", ipAddress, userAgent);

                return new RoleAssignmentResult
                {
                    IsSuccess = true,
                    Message = $"Role {roleName} assigned successfully"
                };
            }
            catch (Exception ex)
            {
                await _auditLogger.LogAsync(assignedBy, "ROLE_ASSIGNMENT_ERROR", $"Role assignment error: {ex.Message}", ipAddress, userAgent);
                return new RoleAssignmentResult
                {
                    IsSuccess = false,
                    ErrorMessage = "An error occurred while assigning the role"
                };
            }
        }

        /// <summary>
        /// Removes a role from a user
        /// </summary>
        /// <param name="userId">User ID</param>
        /// <param name="roleName">Role name</param>
        /// <param name="removedBy">User ID who removed the role</param>
        /// <param name="ipAddress">Client IP address</param>
        /// <param name="userAgent">Client user agent</param>
        /// <returns>Removal result</returns>
        public async Task<RoleAssignmentResult> RemoveRoleFromUserAsync(int userId, string roleName, int removedBy, string ipAddress, string userAgent)
        {
            try
            {
                if (userId <= 0 || string.IsNullOrWhiteSpace(roleName) || removedBy <= 0)
                {
                    await _auditLogger.LogAsync(removedBy, "ROLE_REMOVAL_FAILED", $"Invalid parameters: userId={userId}, role={roleName}", ipAddress, userAgent);
                    return new RoleAssignmentResult
                    {
                        IsSuccess = false,
                        ErrorMessage = "Invalid parameters"
                    };
                }

                // Check if the remover has permission to remove roles
                bool canRemoveRoles = await UserCanPerformActionAsync(removedBy, "RemoveRole");
                if (!canRemoveRoles)
                {
                    await _auditLogger.LogAsync(removedBy, "ROLE_REMOVAL_DENIED", $"User {removedBy} attempted to remove role {roleName} from user {userId}", ipAddress, userAgent);
                    return new RoleAssignmentResult
                    {
                        IsSuccess = false,
                        ErrorMessage = "Insufficient permissions to remove roles"
                    };
                }

                // Check if user has the role
                bool hasRole = await UserHasRoleAsync(userId, roleName);
                if (!hasRole)
                {
                    await _auditLogger.LogAsync(removedBy, "ROLE_REMOVAL_FAILED", $"User {userId} does not have role {roleName}", ipAddress, userAgent);
                    return new RoleAssignmentResult
                    {
                        IsSuccess = false,
                        ErrorMessage = "User does not have this role"
                    };
                }

                // Remove the role
                await _dbManager.RemoveRoleFromUserAsync(userId, roleName);

                await _auditLogger.LogAsync(removedBy, "ROLE_REMOVAL_SUCCESS", $"Removed role {roleName} from user {userId}", ipAddress, userAgent);

                return new RoleAssignmentResult
                {
                    IsSuccess = true,
                    Message = $"Role {roleName} removed successfully"
                };
            }
            catch (Exception ex)
            {
                await _auditLogger.LogAsync(removedBy, "ROLE_REMOVAL_ERROR", $"Role removal error: {ex.Message}", ipAddress, userAgent);
                return new RoleAssignmentResult
                {
                    IsSuccess = false,
                    ErrorMessage = "An error occurred while removing the role"
                };
            }
        }

        /// <summary>
        /// Gets all available roles
        /// </summary>
        /// <returns>List of roles</returns>
        public async Task<List<Role>> GetAllRolesAsync()
        {
            try
            {
                return await _dbManager.GetAllRolesAsync();
            }
            catch
            {
                return new List<Role>();
            }
        }

        /// <summary>
        /// Gets all permissions for a role
        /// </summary>
        /// <param name="roleName">Role name</param>
        /// <returns>List of permissions</returns>
        public async Task<List<Permission>> GetRolePermissionsAsync(string roleName)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(roleName))
                    return new List<Permission>();

                return await _dbManager.GetRolePermissionsAsync(new[] { roleName });
            }
            catch
            {
                return new List<Permission>();
            }
        }
    }

    /// <summary>
    /// Authorization result model
    /// </summary>
    public class AuthorizationResult
    {
        public bool IsAuthorized { get; set; }
        public string Message { get; set; }
        public string ErrorMessage { get; set; }
    }

    /// <summary>
    /// Session authorization result model
    /// </summary>
    public class SessionAuthorizationResult
    {
        public bool IsAuthorized { get; set; }
        public int UserId { get; set; }
        public string Username { get; set; }
        public string Email { get; set; }
        public List<string> Roles { get; set; }
        public string SessionId { get; set; }
        public string Message { get; set; }
        public string ErrorMessage { get; set; }
    }

    /// <summary>
    /// Role assignment result model
    /// </summary>
    public class RoleAssignmentResult
    {
        public bool IsSuccess { get; set; }
        public string Message { get; set; }
        public string ErrorMessage { get; set; }
    }

    /// <summary>
    /// Role model
    /// </summary>
    public class Role
    {
        public int RoleId { get; set; }
        public string RoleName { get; set; }
        public string Description { get; set; }
        public bool IsActive { get; set; }
        public DateTime CreatedAt { get; set; }
    }

    /// <summary>
    /// Permission model
    /// </summary>
    public class Permission
    {
        public int PermissionId { get; set; }
        public string Action { get; set; }
        public string Resource { get; set; }
        public string Description { get; set; }
    }
}
