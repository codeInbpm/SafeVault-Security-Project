using NUnit.Framework;
using SafeVault.Services;
using SafeVault.Data;
using System;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Linq;

namespace SafeVault.Tests
{
    /// <summary>
    /// Comprehensive test suite for authorization system
    /// Tests role-based access control (RBAC) and permission management
    /// </summary>
    [TestFixture]
    public class TestAuthorization
    {
        private AuthorizationService _authzService;
        private AuthenticationService _authService;
        private SessionManager _sessionManager;
        private SecureDatabaseManager _dbManager;
        private AuditLogger _auditLogger;
        private string _connectionString;

        [SetUp]
        public void Setup()
        {
            _connectionString = "Server=localhost;Database=SafeVault;Integrated Security=true;TrustServerCertificate=true;";
            _dbManager = new SecureDatabaseManager(_connectionString);
            _sessionManager = new SessionManager(_dbManager);
            _auditLogger = new AuditLogger(_dbManager);
            _authService = new AuthenticationService(_dbManager, _sessionManager, _auditLogger);
            _authzService = new AuthorizationService(_dbManager, _sessionManager, _auditLogger);
        }

        [TearDown]
        public void TearDown()
        {
            _dbManager?.Dispose();
        }

        [Test]
        public async Task TestUserHasRole_Success()
        {
            // Register a user
            var registerResult = await _authService.RegisterUserAsync(
                "roleuser1",
                "roleuser1@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsTrue(registerResult.IsSuccess, "User registration should succeed");

            // Check if user has default User role
            bool hasUserRole = await _authzService.UserHasRoleAsync(registerResult.UserId, "User");
            Assert.IsTrue(hasUserRole, "User should have default User role");

            // Check if user doesn't have Admin role
            bool hasAdminRole = await _authzService.UserHasRoleAsync(registerResult.UserId, "Admin");
            Assert.IsFalse(hasAdminRole, "User should not have Admin role");
        }

        [Test]
        public async Task TestUserHasRole_InvalidInputs()
        {
            var invalidInputs = new List<(int userId, string roleName)>
            {
                (0, "User"),
                (-1, "User"),
                (1, ""),
                (1, null),
                (0, ""),
                (-1, null)
            };

            foreach (var (userId, roleName) in invalidInputs)
            {
                bool hasRole = await _authzService.UserHasRoleAsync(userId, roleName);
                Assert.IsFalse(hasRole, $"User {userId} should not have role {roleName}");
            }
        }

        [Test]
        public async Task TestUserHasAnyRole_Success()
        {
            // Register a user
            var registerResult = await _authService.RegisterUserAsync(
                "anyroleuser",
                "anyroleuser@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsTrue(registerResult.IsSuccess, "User registration should succeed");

            // Check if user has any of the specified roles
            bool hasAnyRole = await _authzService.UserHasAnyRoleAsync(registerResult.UserId, "User", "Admin", "Manager");
            Assert.IsTrue(hasAnyRole, "User should have at least one of the specified roles");

            // Check if user has any of the specified roles (none match)
            bool hasNoneRole = await _authzService.UserHasAnyRoleAsync(registerResult.UserId, "Admin", "Manager", "Auditor");
            Assert.IsFalse(hasNoneRole, "User should not have any of the specified roles");
        }

        [Test]
        public async Task TestUserHasAnyRole_InvalidInputs()
        {
            var invalidInputs = new List<(int userId, string[] roleNames)>
            {
                (0, new[] { "User" }),
                (-1, new[] { "User" }),
                (1, new string[0]),
                (1, null),
                (0, new string[0]),
                (-1, null)
            };

            foreach (var (userId, roleNames) in invalidInputs)
            {
                bool hasAnyRole = await _authzService.UserHasAnyRoleAsync(userId, roleNames);
                Assert.IsFalse(hasAnyRole, $"User {userId} should not have any of the specified roles");
            }
        }

        [Test]
        public async Task TestUserHasAllRoles_Success()
        {
            // Register a user
            var registerResult = await _authService.RegisterUserAsync(
                "allroleuser",
                "allroleuser@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsTrue(registerResult.IsSuccess, "User registration should succeed");

            // Check if user has all of the specified roles (only User role)
            bool hasAllRoles = await _authzService.UserHasAllRolesAsync(registerResult.UserId, "User");
            Assert.IsTrue(hasAllRoles, "User should have all specified roles");

            // Check if user has all of the specified roles (User and Admin)
            bool hasAllRoles2 = await _authzService.UserHasAllRolesAsync(registerResult.UserId, "User", "Admin");
            Assert.IsFalse(hasAllRoles2, "User should not have all specified roles");
        }

        [Test]
        public async Task TestUserHasAllRoles_InvalidInputs()
        {
            var invalidInputs = new List<(int userId, string[] roleNames)>
            {
                (0, new[] { "User" }),
                (-1, new[] { "User" }),
                (1, new string[0]),
                (1, null),
                (0, new string[0]),
                (-1, null)
            };

            foreach (var (userId, roleNames) in invalidInputs)
            {
                bool hasAllRoles = await _authzService.UserHasAllRolesAsync(userId, roleNames);
                Assert.IsFalse(hasAllRoles, $"User {userId} should not have all of the specified roles");
            }
        }

        [Test]
        public async Task TestUserCanPerformAction_Success()
        {
            // Register a user
            var registerResult = await _authService.RegisterUserAsync(
                "actionuser",
                "actionuser@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsTrue(registerResult.IsSuccess, "User registration should succeed");

            // Check if user can perform basic actions
            bool canReadUser = await _authzService.UserCanPerformActionAsync(registerResult.UserId, "ReadUser");
            Assert.IsTrue(canReadUser, "User should be able to read user information");

            bool canViewReports = await _authzService.UserCanPerformActionAsync(registerResult.UserId, "ViewReports");
            Assert.IsTrue(canViewReports, "User should be able to view reports");

            // Check if user cannot perform admin actions
            bool canCreateUser = await _authzService.UserCanPerformActionAsync(registerResult.UserId, "CreateUser");
            Assert.IsFalse(canCreateUser, "User should not be able to create users");

            bool canAssignRole = await _authzService.UserCanPerformActionAsync(registerResult.UserId, "AssignRole");
            Assert.IsFalse(canAssignRole, "User should not be able to assign roles");
        }

        [Test]
        public async Task TestUserCanPerformAction_InvalidInputs()
        {
            var invalidInputs = new List<(int userId, string action, string resource)>
            {
                (0, "ReadUser", null),
                (-1, "ReadUser", null),
                (1, "", null),
                (1, null, null),
                (0, "", null),
                (-1, null, null)
            };

            foreach (var (userId, action, resource) in invalidInputs)
            {
                bool canPerform = await _authzService.UserCanPerformActionAsync(userId, action, resource);
                Assert.IsFalse(canPerform, $"User {userId} should not be able to perform action {action}");
            }
        }

        [Test]
        public async Task TestAuthorizeUser_Success()
        {
            // Register a user
            var registerResult = await _authService.RegisterUserAsync(
                "authuser",
                "authuser@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsTrue(registerResult.IsSuccess, "User registration should succeed");

            // Authorize user for allowed action
            var authResult = await _authzService.AuthorizeUserAsync(
                registerResult.UserId,
                "ReadUser",
                null,
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsTrue(authResult.IsAuthorized, "User should be authorized for ReadUser action");
            Assert.AreEqual("Access granted", authResult.Message);

            // Authorize user for denied action
            var authResult2 = await _authzService.AuthorizeUserAsync(
                registerResult.UserId,
                "CreateUser",
                null,
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsFalse(authResult2.IsAuthorized, "User should not be authorized for CreateUser action");
            Assert.AreEqual("Access denied", authResult2.ErrorMessage);
        }

        [Test]
        public async Task TestAuthorizeUser_InvalidInputs()
        {
            var invalidInputs = new List<(int userId, string action, string resource)>
            {
                (0, "ReadUser", null),
                (-1, "ReadUser", null),
                (1, "", null),
                (1, null, null),
                (0, "", null),
                (-1, null, null)
            };

            foreach (var (userId, action, resource) in invalidInputs)
            {
                var authResult = await _authzService.AuthorizeUserAsync(
                    userId,
                    action,
                    resource,
                    "127.0.0.1",
                    "TestAgent"
                );

                Assert.IsFalse(authResult.IsAuthorized, $"User {userId} should not be authorized for action {action}");
                Assert.AreEqual("Invalid authorization parameters", authResult.ErrorMessage);
            }
        }

        [Test]
        public async Task TestAuthorizeSession_Success()
        {
            // Register a user
            var registerResult = await _authService.RegisterUserAsync(
                "sessionauthuser",
                "sessionauthuser@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsTrue(registerResult.IsSuccess, "User registration should succeed");

            // Authenticate the user
            var authResult = await _authService.AuthenticateUserAsync(
                "sessionauthuser",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsTrue(authResult.IsSuccess, "Authentication should succeed");

            // Authorize session for allowed action
            var sessionAuthResult = await _authzService.AuthorizeSessionAsync(
                authResult.Token,
                "ReadUser",
                null,
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsTrue(sessionAuthResult.IsAuthorized, "Session should be authorized for ReadUser action");
            Assert.AreEqual(registerResult.UserId, sessionAuthResult.UserId, "User IDs should match");
            Assert.AreEqual("sessionauthuser", sessionAuthResult.Username, "Usernames should match");
            Assert.AreEqual("sessionauthuser@example.com", sessionAuthResult.Email, "Emails should match");
            Assert.IsNotNull(sessionAuthResult.Roles, "Roles should not be null");
            Assert.IsTrue(sessionAuthResult.Roles.Contains("User"), "User should have User role");

            // Authorize session for denied action
            var sessionAuthResult2 = await _authzService.AuthorizeSessionAsync(
                authResult.Token,
                "CreateUser",
                null,
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsFalse(sessionAuthResult2.IsAuthorized, "Session should not be authorized for CreateUser action");
            Assert.AreEqual("Access denied", sessionAuthResult2.ErrorMessage);
        }

        [Test]
        public async Task TestAuthorizeSession_InvalidToken()
        {
            // Try to authorize with invalid token
            var sessionAuthResult = await _authzService.AuthorizeSessionAsync(
                "invalid-token",
                "ReadUser",
                null,
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsFalse(sessionAuthResult.IsAuthorized, "Invalid token should not be authorized");
            Assert.AreEqual("Invalid or expired session", sessionAuthResult.ErrorMessage);
        }

        [Test]
        public async Task TestAuthorizeSession_EmptyToken()
        {
            // Try to authorize with empty token
            var sessionAuthResult = await _authzService.AuthorizeSessionAsync(
                "",
                "ReadUser",
                null,
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsFalse(sessionAuthResult.IsAuthorized, "Empty token should not be authorized");
            Assert.AreEqual("Token is required", sessionAuthResult.ErrorMessage);
        }

        [Test]
        public async Task TestAssignRoleToUser_Success()
        {
            // Register two users
            var registerResult1 = await _authService.RegisterUserAsync(
                "assigner",
                "assigner@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            var registerResult2 = await _authService.RegisterUserAsync(
                "assignee",
                "assignee@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsTrue(registerResult1.IsSuccess, "First user registration should succeed");
            Assert.IsTrue(registerResult2.IsSuccess, "Second user registration should succeed");

            // Assign Admin role to the first user (this would normally require admin privileges)
            // For testing purposes, we'll simulate this by directly assigning the role
            await _dbManager.AssignRoleToUserAsync(registerResult1.UserId, "Admin");

            // Now the first user should be able to assign roles
            var assignResult = await _authzService.AssignRoleToUserAsync(
                registerResult2.UserId,
                "Manager",
                registerResult1.UserId,
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsTrue(assignResult.IsSuccess, "Role assignment should succeed");
            Assert.AreEqual("Role Manager assigned successfully", assignResult.Message);

            // Verify the role was assigned
            bool hasManagerRole = await _authzService.UserHasRoleAsync(registerResult2.UserId, "Manager");
            Assert.IsTrue(hasManagerRole, "User should have Manager role");
        }

        [Test]
        public async Task TestAssignRoleToUser_InvalidInputs()
        {
            var invalidInputs = new List<(int userId, string roleName, int assignedBy)>
            {
                (0, "Manager", 1),
                (-1, "Manager", 1),
                (1, "", 1),
                (1, null, 1),
                (1, "Manager", 0),
                (1, "Manager", -1),
                (0, "", 0),
                (-1, null, -1)
            };

            foreach (var (userId, roleName, assignedBy) in invalidInputs)
            {
                var assignResult = await _authzService.AssignRoleToUserAsync(
                    userId,
                    roleName,
                    assignedBy,
                    "127.0.0.1",
                    "TestAgent"
                );

                Assert.IsFalse(assignResult.IsSuccess, $"Role assignment should fail for: userId={userId}, role={roleName}, assignedBy={assignedBy}");
                Assert.AreEqual("Invalid parameters", assignResult.ErrorMessage);
            }
        }

        [Test]
        public async Task TestAssignRoleToUser_InsufficientPermissions()
        {
            // Register two users
            var registerResult1 = await _authService.RegisterUserAsync(
                "assigner2",
                "assigner2@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            var registerResult2 = await _authService.RegisterUserAsync(
                "assignee2",
                "assignee2@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsTrue(registerResult1.IsSuccess, "First user registration should succeed");
            Assert.IsTrue(registerResult2.IsSuccess, "Second user registration should succeed");

            // Try to assign role without proper permissions
            var assignResult = await _authzService.AssignRoleToUserAsync(
                registerResult2.UserId,
                "Manager",
                registerResult1.UserId,
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsFalse(assignResult.IsSuccess, "Role assignment should fail without proper permissions");
            Assert.AreEqual("Insufficient permissions to assign roles", assignResult.ErrorMessage);
        }

        [Test]
        public async Task TestAssignRoleToUser_RoleDoesNotExist()
        {
            // Register two users
            var registerResult1 = await _authService.RegisterUserAsync(
                "assigner3",
                "assigner3@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            var registerResult2 = await _authService.RegisterUserAsync(
                "assignee3",
                "assignee3@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsTrue(registerResult1.IsSuccess, "First user registration should succeed");
            Assert.IsTrue(registerResult2.IsSuccess, "Second user registration should succeed");

            // Assign Admin role to the first user
            await _dbManager.AssignRoleToUserAsync(registerResult1.UserId, "Admin");

            // Try to assign non-existent role
            var assignResult = await _authzService.AssignRoleToUserAsync(
                registerResult2.UserId,
                "NonExistentRole",
                registerResult1.UserId,
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsFalse(assignResult.IsSuccess, "Role assignment should fail for non-existent role");
            Assert.AreEqual("Role does not exist", assignResult.ErrorMessage);
        }

        [Test]
        public async Task TestAssignRoleToUser_UserDoesNotExist()
        {
            // Register a user
            var registerResult = await _authService.RegisterUserAsync(
                "assigner4",
                "assigner4@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsTrue(registerResult.IsSuccess, "User registration should succeed");

            // Assign Admin role to the user
            await _dbManager.AssignRoleToUserAsync(registerResult.UserId, "Admin");

            // Try to assign role to non-existent user
            var assignResult = await _authzService.AssignRoleToUserAsync(
                99999, // Non-existent user ID
                "Manager",
                registerResult.UserId,
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsFalse(assignResult.IsSuccess, "Role assignment should fail for non-existent user");
            Assert.AreEqual("User does not exist", assignResult.ErrorMessage);
        }

        [Test]
        public async Task TestAssignRoleToUser_UserAlreadyHasRole()
        {
            // Register two users
            var registerResult1 = await _authService.RegisterUserAsync(
                "assigner5",
                "assigner5@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            var registerResult2 = await _authService.RegisterUserAsync(
                "assignee5",
                "assignee5@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsTrue(registerResult1.IsSuccess, "First user registration should succeed");
            Assert.IsTrue(registerResult2.IsSuccess, "Second user registration should succeed");

            // Assign Admin role to the first user
            await _dbManager.AssignRoleToUserAsync(registerResult1.UserId, "Admin");

            // Try to assign User role to the second user (they already have it)
            var assignResult = await _authzService.AssignRoleToUserAsync(
                registerResult2.UserId,
                "User",
                registerResult1.UserId,
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsFalse(assignResult.IsSuccess, "Role assignment should fail for existing role");
            Assert.AreEqual("User already has this role", assignResult.ErrorMessage);
        }

        [Test]
        public async Task TestRemoveRoleFromUser_Success()
        {
            // Register two users
            var registerResult1 = await _authService.RegisterUserAsync(
                "remover",
                "remover@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            var registerResult2 = await _authService.RegisterUserAsync(
                "removee",
                "removee@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsTrue(registerResult1.IsSuccess, "First user registration should succeed");
            Assert.IsTrue(registerResult2.IsSuccess, "Second user registration should succeed");

            // Assign Admin role to the first user
            await _dbManager.AssignRoleToUserAsync(registerResult1.UserId, "Admin");

            // Assign Manager role to the second user
            await _dbManager.AssignRoleToUserAsync(registerResult2.UserId, "Manager");

            // Verify the role was assigned
            bool hasManagerRole = await _authzService.UserHasRoleAsync(registerResult2.UserId, "Manager");
            Assert.IsTrue(hasManagerRole, "User should have Manager role");

            // Remove the Manager role
            var removeResult = await _authzService.RemoveRoleFromUserAsync(
                registerResult2.UserId,
                "Manager",
                registerResult1.UserId,
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsTrue(removeResult.IsSuccess, "Role removal should succeed");
            Assert.AreEqual("Role Manager removed successfully", removeResult.Message);

            // Verify the role was removed
            bool hasManagerRoleAfter = await _authzService.UserHasRoleAsync(registerResult2.UserId, "Manager");
            Assert.IsFalse(hasManagerRoleAfter, "User should not have Manager role after removal");
        }

        [Test]
        public async Task TestRemoveRoleFromUser_InvalidInputs()
        {
            var invalidInputs = new List<(int userId, string roleName, int removedBy)>
            {
                (0, "Manager", 1),
                (-1, "Manager", 1),
                (1, "", 1),
                (1, null, 1),
                (1, "Manager", 0),
                (1, "Manager", -1),
                (0, "", 0),
                (-1, null, -1)
            };

            foreach (var (userId, roleName, removedBy) in invalidInputs)
            {
                var removeResult = await _authzService.RemoveRoleFromUserAsync(
                    userId,
                    roleName,
                    removedBy,
                    "127.0.0.1",
                    "TestAgent"
                );

                Assert.IsFalse(removeResult.IsSuccess, $"Role removal should fail for: userId={userId}, role={roleName}, removedBy={removedBy}");
                Assert.AreEqual("Invalid parameters", removeResult.ErrorMessage);
            }
        }

        [Test]
        public async Task TestRemoveRoleFromUser_InsufficientPermissions()
        {
            // Register two users
            var registerResult1 = await _authService.RegisterUserAsync(
                "remover2",
                "remover2@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            var registerResult2 = await _authService.RegisterUserAsync(
                "removee2",
                "removee2@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsTrue(registerResult1.IsSuccess, "First user registration should succeed");
            Assert.IsTrue(registerResult2.IsSuccess, "Second user registration should succeed");

            // Assign Manager role to the second user
            await _dbManager.AssignRoleToUserAsync(registerResult2.UserId, "Manager");

            // Try to remove role without proper permissions
            var removeResult = await _authzService.RemoveRoleFromUserAsync(
                registerResult2.UserId,
                "Manager",
                registerResult1.UserId,
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsFalse(removeResult.IsSuccess, "Role removal should fail without proper permissions");
            Assert.AreEqual("Insufficient permissions to remove roles", removeResult.ErrorMessage);
        }

        [Test]
        public async Task TestRemoveRoleFromUser_UserDoesNotHaveRole()
        {
            // Register two users
            var registerResult1 = await _authService.RegisterUserAsync(
                "remover3",
                "remover3@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            var registerResult2 = await _authService.RegisterUserAsync(
                "removee3",
                "removee3@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsTrue(registerResult1.IsSuccess, "First user registration should succeed");
            Assert.IsTrue(registerResult2.IsSuccess, "Second user registration should succeed");

            // Assign Admin role to the first user
            await _dbManager.AssignRoleToUserAsync(registerResult1.UserId, "Admin");

            // Try to remove Manager role from user who doesn't have it
            var removeResult = await _authzService.RemoveRoleFromUserAsync(
                registerResult2.UserId,
                "Manager",
                registerResult1.UserId,
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsFalse(removeResult.IsSuccess, "Role removal should fail for user who doesn't have the role");
            Assert.AreEqual("User does not have this role", removeResult.ErrorMessage);
        }

        [Test]
        public async Task TestGetAllRoles_Success()
        {
            // Get all roles
            var roles = await _authzService.GetAllRolesAsync();

            Assert.IsNotNull(roles, "Roles should not be null");
            Assert.IsTrue(roles.Count > 0, "Should have at least one role");

            // Check for expected default roles
            var roleNames = roles.Select(r => r.RoleName).ToList();
            Assert.IsTrue(roleNames.Contains("Admin"), "Should have Admin role");
            Assert.IsTrue(roleNames.Contains("User"), "Should have User role");
            Assert.IsTrue(roleNames.Contains("Manager"), "Should have Manager role");
            Assert.IsTrue(roleNames.Contains("Auditor"), "Should have Auditor role");
        }

        [Test]
        public async Task TestGetRolePermissions_Success()
        {
            // Get permissions for Admin role
            var adminPermissions = await _authzService.GetRolePermissionsAsync("Admin");

            Assert.IsNotNull(adminPermissions, "Admin permissions should not be null");
            Assert.IsTrue(adminPermissions.Count > 0, "Admin should have permissions");

            // Check for expected permissions
            var permissionActions = adminPermissions.Select(p => p.Action).ToList();
            Assert.IsTrue(permissionActions.Contains("CreateUser"), "Admin should have CreateUser permission");
            Assert.IsTrue(permissionActions.Contains("AssignRole"), "Admin should have AssignRole permission");
            Assert.IsTrue(permissionActions.Contains("AccessAdminPanel"), "Admin should have AccessAdminPanel permission");

            // Get permissions for User role
            var userPermissions = await _authzService.GetRolePermissionsAsync("User");

            Assert.IsNotNull(userPermissions, "User permissions should not be null");
            Assert.IsTrue(userPermissions.Count > 0, "User should have permissions");

            // Check for expected permissions
            var userPermissionActions = userPermissions.Select(p => p.Action).ToList();
            Assert.IsTrue(userPermissionActions.Contains("ReadUser"), "User should have ReadUser permission");
            Assert.IsTrue(userPermissionActions.Contains("ViewReports"), "User should have ViewReports permission");
            Assert.IsFalse(userPermissionActions.Contains("CreateUser"), "User should not have CreateUser permission");
            Assert.IsFalse(userPermissionActions.Contains("AssignRole"), "User should not have AssignRole permission");
        }

        [Test]
        public async Task TestGetRolePermissions_InvalidRole()
        {
            // Get permissions for non-existent role
            var permissions = await _authzService.GetRolePermissionsAsync("NonExistentRole");

            Assert.IsNotNull(permissions, "Permissions should not be null");
            Assert.AreEqual(0, permissions.Count, "Non-existent role should have no permissions");
        }

        [Test]
        public async Task TestGetRolePermissions_EmptyRole()
        {
            // Get permissions for empty role
            var permissions = await _authzService.GetRolePermissionsAsync("");

            Assert.IsNotNull(permissions, "Permissions should not be null");
            Assert.AreEqual(0, permissions.Count, "Empty role should have no permissions");
        }

        [Test]
        public async Task TestConcurrentAuthorization()
        {
            // Test concurrent authorization requests
            var tasks = new List<Task<AuthorizationResult>>();
            
            for (int i = 0; i < 10; i++)
            {
                int index = i;
                tasks.Add(Task.Run(async () =>
                {
                    // Register a user for each task
                    var registerResult = await _authService.RegisterUserAsync(
                        $"concurrentauthuser{index}",
                        $"concurrentauthuser{index}@example.com",
                        "SecurePass123!",
                        "127.0.0.1",
                        "TestAgent"
                    );

                    if (registerResult.IsSuccess)
                    {
                        // Authorize the user
                        return await _authzService.AuthorizeUserAsync(
                            registerResult.UserId,
                            "ReadUser",
                            null,
                            "127.0.0.1",
                            "TestAgent"
                        );
                    }
                    else
                    {
                        return new AuthorizationResult { IsAuthorized = false };
                    }
                }));
            }

            var results = await Task.WhenAll(tasks);
            
            // Check that all authorizations succeeded
            foreach (var result in results)
            {
                Assert.IsTrue(result.IsAuthorized, "Concurrent authorization should succeed");
            }
        }

        [Test]
        public async Task TestErrorHandling()
        {
            // Test error handling for various scenarios
            try
            {
                // Test with null parameters
                var result = await _authzService.AuthorizeUserAsync(0, null, null, null, null);
                Assert.IsFalse(result.IsAuthorized, "Authorization should fail with null parameters");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex.Message.Contains("null") || ex.Message.Contains("Null"), 
                    $"Expected null parameter error: {ex.Message}");
            }

            try
            {
                // Test with empty parameters
                var result = await _authzService.AuthorizeUserAsync(0, "", "", "", "");
                Assert.IsFalse(result.IsAuthorized, "Authorization should fail with empty parameters");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex.Message.Contains("required") || ex.Message.Contains("empty"), 
                    $"Expected empty parameter error: {ex.Message}");
            }
        }
    }
}
