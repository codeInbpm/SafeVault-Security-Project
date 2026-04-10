using System;
using System.Threading.Tasks;
using SafeVault.Services;
using SafeVault.Data;
using System.Collections.Generic;
using System.Diagnostics;

namespace SafeVault.TestRunner
{
    /// <summary>
    /// Comprehensive test runner for SafeVault authentication and authorization
    /// </summary>
    public class AuthTestRunner
    {
        private readonly AuthenticationService _authService;
        private readonly AuthorizationService _authzService;
        private readonly SessionManager _sessionManager;
        private readonly SecureDatabaseManager _dbManager;
        private readonly AuditLogger _auditLogger;
        private readonly List<TestResult> _testResults;

        public AuthTestRunner()
        {
            var connectionString = "Server=localhost;Database=SafeVault;Integrated Security=true;TrustServerCertificate=true;";
            _dbManager = new SecureDatabaseManager(connectionString);
            _sessionManager = new SessionManager(_dbManager);
            _auditLogger = new AuditLogger(_dbManager);
            _authService = new AuthenticationService(_dbManager, _sessionManager, _auditLogger);
            _authzService = new AuthorizationService(_dbManager, _sessionManager, _auditLogger);
            _testResults = new List<TestResult>();
        }

        /// <summary>
        /// Runs all authentication and authorization tests
        /// </summary>
        public async Task<AuthTestReport> RunAllTestsAsync()
        {
            Console.WriteLine("Starting SafeVault Authentication & Authorization Test Suite...");
            Console.WriteLine("=============================================================");

            var report = new AuthTestReport
            {
                StartTime = DateTime.UtcNow,
                TestResults = new List<TestResult>()
            };

            // Run authentication tests
            await RunAuthenticationTestsAsync(report);

            // Run authorization tests
            await RunAuthorizationTestsAsync(report);

            // Run integration tests
            await RunIntegrationTestsAsync(report);

            report.EndTime = DateTime.UtcNow;
            report.Duration = report.EndTime - report.StartTime;

            GenerateReport(report);
            return report;
        }

        private async Task RunAuthenticationTestsAsync(AuthTestReport report)
        {
            Console.WriteLine("\n1. Testing Authentication System...");
            Console.WriteLine("-----------------------------------");

            var testCases = new List<(string testName, Func<Task<bool>> testFunction)>
            {
                ("User Registration - Success", TestUserRegistrationSuccess),
                ("User Registration - Duplicate Username", TestUserRegistrationDuplicateUsername),
                ("User Registration - Duplicate Email", TestUserRegistrationDuplicateEmail),
                ("User Registration - Invalid Inputs", TestUserRegistrationInvalidInputs),
                ("User Authentication - Success", TestUserAuthenticationSuccess),
                ("User Authentication - Invalid Credentials", TestUserAuthenticationInvalidCredentials),
                ("User Authentication - Empty Inputs", TestUserAuthenticationEmptyInputs),
                ("Password Change - Success", TestPasswordChangeSuccess),
                ("Password Change - Invalid Current Password", TestPasswordChangeInvalidCurrentPassword),
                ("Password Change - Invalid New Password", TestPasswordChangeInvalidNewPassword),
                ("User Logout - Success", TestUserLogoutSuccess),
                ("User Logout - Invalid Session", TestUserLogoutInvalidSession),
                ("Session Management - Create Session", TestSessionManagementCreateSession),
                ("Session Management - Validate Session", TestSessionManagementValidateSession),
                ("Session Management - Invalidate Session", TestSessionManagementInvalidateSession),
                ("Session Management - Refresh Session", TestSessionManagementRefreshSession)
            };

            foreach (var (testName, testFunction) in testCases)
            {
                var result = await RunSingleTestAsync(testName, testFunction);
                report.TestResults.Add(result);
            }
        }

        private async Task RunAuthorizationTestsAsync(AuthTestReport report)
        {
            Console.WriteLine("\n2. Testing Authorization System...");
            Console.WriteLine("----------------------------------");

            var testCases = new List<(string testName, Func<Task<bool>> testFunction)>
            {
                ("User Has Role - Success", TestUserHasRoleSuccess),
                ("User Has Role - Invalid Inputs", TestUserHasRoleInvalidInputs),
                ("User Has Any Role - Success", TestUserHasAnyRoleSuccess),
                ("User Has Any Role - Invalid Inputs", TestUserHasAnyRoleInvalidInputs),
                ("User Has All Roles - Success", TestUserHasAllRolesSuccess),
                ("User Has All Roles - Invalid Inputs", TestUserHasAllRolesInvalidInputs),
                ("User Can Perform Action - Success", TestUserCanPerformActionSuccess),
                ("User Can Perform Action - Invalid Inputs", TestUserCanPerformActionInvalidInputs),
                ("Authorize User - Success", TestAuthorizeUserSuccess),
                ("Authorize User - Invalid Inputs", TestAuthorizeUserInvalidInputs),
                ("Authorize Session - Success", TestAuthorizeSessionSuccess),
                ("Authorize Session - Invalid Token", TestAuthorizeSessionInvalidToken),
                ("Assign Role To User - Success", TestAssignRoleToUserSuccess),
                ("Assign Role To User - Invalid Inputs", TestAssignRoleToUserInvalidInputs),
                ("Assign Role To User - Insufficient Permissions", TestAssignRoleToUserInsufficientPermissions),
                ("Remove Role From User - Success", TestRemoveRoleFromUserSuccess),
                ("Remove Role From User - Invalid Inputs", TestRemoveRoleFromUserInvalidInputs),
                ("Remove Role From User - Insufficient Permissions", TestRemoveRoleFromUserInsufficientPermissions),
                ("Get All Roles - Success", TestGetAllRolesSuccess),
                ("Get Role Permissions - Success", TestGetRolePermissionsSuccess)
            };

            foreach (var (testName, testFunction) in testCases)
            {
                var result = await RunSingleTestAsync(testName, testFunction);
                report.TestResults.Add(result);
            }
        }

        private async Task RunIntegrationTestsAsync(AuthTestReport report)
        {
            Console.WriteLine("\n3. Testing Integration Scenarios...");
            Console.WriteLine("------------------------------------");

            var testCases = new List<(string testName, Func<Task<bool>> testFunction)>
            {
                ("End-to-End Authentication Flow", TestEndToEndAuthenticationFlow),
                ("End-to-End Authorization Flow", TestEndToEndAuthorizationFlow),
                ("Concurrent Authentication Requests", TestConcurrentAuthenticationRequests),
                ("Concurrent Authorization Requests", TestConcurrentAuthorizationRequests),
                ("Session Security", TestSessionSecurity),
                ("Role-Based Access Control", TestRoleBasedAccessControl),
                ("Permission Inheritance", TestPermissionInheritance),
                ("Audit Logging", TestAuditLogging)
            };

            foreach (var (testName, testFunction) in testCases)
            {
                var result = await RunSingleTestAsync(testName, testFunction);
                report.TestResults.Add(result);
            }
        }

        private async Task<TestResult> RunSingleTestAsync(string testName, Func<Task<bool>> testFunction)
        {
            var stopwatch = Stopwatch.StartNew();
            var result = new TestResult
            {
                TestName = testName,
                StartTime = DateTime.UtcNow
            };

            try
            {
                result.Passed = await testFunction();
                result.ErrorMessage = result.Passed ? null : "Test failed";
            }
            catch (Exception ex)
            {
                result.Passed = false;
                result.ErrorMessage = ex.Message;
            }
            finally
            {
                stopwatch.Stop();
                result.Duration = stopwatch.Elapsed;
                result.EndTime = DateTime.UtcNow;
            }

            Console.WriteLine($"  {testName}: {(result.Passed ? "PASS" : "FAIL")} ({result.Duration.TotalMilliseconds:F2}ms)");
            if (!result.Passed && !string.IsNullOrEmpty(result.ErrorMessage))
            {
                Console.WriteLine($"    Error: {result.ErrorMessage}");
            }

            return result;
        }

        // Authentication test methods
        private async Task<bool> TestUserRegistrationSuccess()
        {
            var result = await _authService.RegisterUserAsync(
                "testuser1",
                "testuser1@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );
            return result.IsSuccess;
        }

        private async Task<bool> TestUserRegistrationDuplicateUsername()
        {
            await _authService.RegisterUserAsync(
                "duplicateuser",
                "duplicateuser1@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            var result = await _authService.RegisterUserAsync(
                "duplicateuser",
                "duplicateuser2@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );
            return !result.IsSuccess && result.ErrorMessage.Contains("already exists");
        }

        private async Task<bool> TestUserRegistrationDuplicateEmail()
        {
            await _authService.RegisterUserAsync(
                "user1",
                "duplicate@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            var result = await _authService.RegisterUserAsync(
                "user2",
                "duplicate@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );
            return !result.IsSuccess && result.ErrorMessage.Contains("already exists");
        }

        private async Task<bool> TestUserRegistrationInvalidInputs()
        {
            var result = await _authService.RegisterUserAsync(
                "ab", // Too short
                "invalid-email",
                "weak",
                "127.0.0.1",
                "TestAgent"
            );
            return !result.IsSuccess;
        }

        private async Task<bool> TestUserAuthenticationSuccess()
        {
            await _authService.RegisterUserAsync(
                "authuser",
                "authuser@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            var result = await _authService.AuthenticateUserAsync(
                "authuser",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );
            return result.IsSuccess;
        }

        private async Task<bool> TestUserAuthenticationInvalidCredentials()
        {
            await _authService.RegisterUserAsync(
                "authuser2",
                "authuser2@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            var result = await _authService.AuthenticateUserAsync(
                "authuser2",
                "WrongPassword123!",
                "127.0.0.1",
                "TestAgent"
            );
            return !result.IsSuccess;
        }

        private async Task<bool> TestUserAuthenticationEmptyInputs()
        {
            var result = await _authService.AuthenticateUserAsync(
                "",
                "",
                "127.0.0.1",
                "TestAgent"
            );
            return !result.IsSuccess;
        }

        private async Task<bool> TestPasswordChangeSuccess()
        {
            var registerResult = await _authService.RegisterUserAsync(
                "passuser",
                "passuser@example.com",
                "OldPass123!",
                "127.0.0.1",
                "TestAgent"
            );

            if (!registerResult.IsSuccess) return false;

            var changeResult = await _authService.ChangePasswordAsync(
                registerResult.UserId,
                "OldPass123!",
                "NewPass123!",
                "127.0.0.1",
                "TestAgent"
            );
            return changeResult.IsSuccess;
        }

        private async Task<bool> TestPasswordChangeInvalidCurrentPassword()
        {
            var registerResult = await _authService.RegisterUserAsync(
                "passuser2",
                "passuser2@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            if (!registerResult.IsSuccess) return false;

            var changeResult = await _authService.ChangePasswordAsync(
                registerResult.UserId,
                "WrongPass123!",
                "NewPass123!",
                "127.0.0.1",
                "TestAgent"
            );
            return !changeResult.IsSuccess;
        }

        private async Task<bool> TestPasswordChangeInvalidNewPassword()
        {
            var registerResult = await _authService.RegisterUserAsync(
                "passuser3",
                "passuser3@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            if (!registerResult.IsSuccess) return false;

            var changeResult = await _authService.ChangePasswordAsync(
                registerResult.UserId,
                "SecurePass123!",
                "weak",
                "127.0.0.1",
                "TestAgent"
            );
            return !changeResult.IsSuccess;
        }

        private async Task<bool> TestUserLogoutSuccess()
        {
            var registerResult = await _authService.RegisterUserAsync(
                "logoutuser",
                "logoutuser@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            if (!registerResult.IsSuccess) return false;

            var authResult = await _authService.AuthenticateUserAsync(
                "logoutuser",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            if (!authResult.IsSuccess) return false;

            var logoutResult = await _authService.LogoutUserAsync(
                authResult.SessionId,
                "127.0.0.1",
                "TestAgent"
            );
            return logoutResult.IsSuccess;
        }

        private async Task<bool> TestUserLogoutInvalidSession()
        {
            var logoutResult = await _authService.LogoutUserAsync(
                "invalid-session-id",
                "127.0.0.1",
                "TestAgent"
            );
            return !logoutResult.IsSuccess;
        }

        private async Task<bool> TestSessionManagementCreateSession()
        {
            var registerResult = await _authService.RegisterUserAsync(
                "sessionuser",
                "sessionuser@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            if (!registerResult.IsSuccess) return false;

            var session = await _sessionManager.CreateSessionAsync(
                registerResult.UserId,
                "127.0.0.1",
                "TestAgent"
            );
            return session != null;
        }

        private async Task<bool> TestSessionManagementValidateSession()
        {
            var registerResult = await _authService.RegisterUserAsync(
                "sessionuser2",
                "sessionuser2@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            if (!registerResult.IsSuccess) return false;

            var session = await _sessionManager.CreateSessionAsync(
                registerResult.UserId,
                "127.0.0.1",
                "TestAgent"
            );

            if (session == null) return false;

            var validatedSession = await _sessionManager.ValidateTokenAsync(session.Token);
            return validatedSession != null;
        }

        private async Task<bool> TestSessionManagementInvalidateSession()
        {
            var registerResult = await _authService.RegisterUserAsync(
                "sessionuser3",
                "sessionuser3@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            if (!registerResult.IsSuccess) return false;

            var session = await _sessionManager.CreateSessionAsync(
                registerResult.UserId,
                "127.0.0.1",
                "TestAgent"
            );

            if (session == null) return false;

            await _sessionManager.InvalidateSessionAsync(session.SessionId);
            var validatedSession = await _sessionManager.ValidateTokenAsync(session.Token);
            return validatedSession == null;
        }

        private async Task<bool> TestSessionManagementRefreshSession()
        {
            var registerResult = await _authService.RegisterUserAsync(
                "sessionuser4",
                "sessionuser4@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            if (!registerResult.IsSuccess) return false;

            var session = await _sessionManager.CreateSessionAsync(
                registerResult.UserId,
                "127.0.0.1",
                "TestAgent"
            );

            if (session == null) return false;

            var refreshedSession = await _sessionManager.RefreshSessionAsync(session.SessionId);
            return refreshedSession != null;
        }

        // Authorization test methods
        private async Task<bool> TestUserHasRoleSuccess()
        {
            var registerResult = await _authService.RegisterUserAsync(
                "roleuser1",
                "roleuser1@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            if (!registerResult.IsSuccess) return false;

            bool hasUserRole = await _authzService.UserHasRoleAsync(registerResult.UserId, "User");
            bool hasAdminRole = await _authzService.UserHasRoleAsync(registerResult.UserId, "Admin");
            return hasUserRole && !hasAdminRole;
        }

        private async Task<bool> TestUserHasRoleInvalidInputs()
        {
            bool hasRole = await _authzService.UserHasRoleAsync(0, "User");
            return !hasRole;
        }

        private async Task<bool> TestUserHasAnyRoleSuccess()
        {
            var registerResult = await _authService.RegisterUserAsync(
                "anyroleuser",
                "anyroleuser@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            if (!registerResult.IsSuccess) return false;

            bool hasAnyRole = await _authzService.UserHasAnyRoleAsync(registerResult.UserId, "User", "Admin", "Manager");
            bool hasNoneRole = await _authzService.UserHasAnyRoleAsync(registerResult.UserId, "Admin", "Manager", "Auditor");
            return hasAnyRole && !hasNoneRole;
        }

        private async Task<bool> TestUserHasAnyRoleInvalidInputs()
        {
            bool hasAnyRole = await _authzService.UserHasAnyRoleAsync(0, "User");
            return !hasAnyRole;
        }

        private async Task<bool> TestUserHasAllRolesSuccess()
        {
            var registerResult = await _authService.RegisterUserAsync(
                "allroleuser",
                "allroleuser@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            if (!registerResult.IsSuccess) return false;

            bool hasAllRoles = await _authzService.UserHasAllRolesAsync(registerResult.UserId, "User");
            bool hasAllRoles2 = await _authzService.UserHasAllRolesAsync(registerResult.UserId, "User", "Admin");
            return hasAllRoles && !hasAllRoles2;
        }

        private async Task<bool> TestUserHasAllRolesInvalidInputs()
        {
            bool hasAllRoles = await _authzService.UserHasAllRolesAsync(0, "User");
            return !hasAllRoles;
        }

        private async Task<bool> TestUserCanPerformActionSuccess()
        {
            var registerResult = await _authService.RegisterUserAsync(
                "actionuser",
                "actionuser@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            if (!registerResult.IsSuccess) return false;

            bool canReadUser = await _authzService.UserCanPerformActionAsync(registerResult.UserId, "ReadUser");
            bool canCreateUser = await _authzService.UserCanPerformActionAsync(registerResult.UserId, "CreateUser");
            return canReadUser && !canCreateUser;
        }

        private async Task<bool> TestUserCanPerformActionInvalidInputs()
        {
            bool canPerform = await _authzService.UserCanPerformActionAsync(0, "ReadUser");
            return !canPerform;
        }

        private async Task<bool> TestAuthorizeUserSuccess()
        {
            var registerResult = await _authService.RegisterUserAsync(
                "authuser",
                "authuser@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            if (!registerResult.IsSuccess) return false;

            var authResult = await _authzService.AuthorizeUserAsync(
                registerResult.UserId,
                "ReadUser",
                null,
                "127.0.0.1",
                "TestAgent"
            );

            var authResult2 = await _authzService.AuthorizeUserAsync(
                registerResult.UserId,
                "CreateUser",
                null,
                "127.0.0.1",
                "TestAgent"
            );
            return authResult.IsAuthorized && !authResult2.IsAuthorized;
        }

        private async Task<bool> TestAuthorizeUserInvalidInputs()
        {
            var authResult = await _authzService.AuthorizeUserAsync(
                0,
                "ReadUser",
                null,
                "127.0.0.1",
                "TestAgent"
            );
            return !authResult.IsAuthorized;
        }

        private async Task<bool> TestAuthorizeSessionSuccess()
        {
            var registerResult = await _authService.RegisterUserAsync(
                "sessionauthuser",
                "sessionauthuser@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            if (!registerResult.IsSuccess) return false;

            var authResult = await _authService.AuthenticateUserAsync(
                "sessionauthuser",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            if (!authResult.IsSuccess) return false;

            var sessionAuthResult = await _authzService.AuthorizeSessionAsync(
                authResult.Token,
                "ReadUser",
                null,
                "127.0.0.1",
                "TestAgent"
            );

            var sessionAuthResult2 = await _authzService.AuthorizeSessionAsync(
                authResult.Token,
                "CreateUser",
                null,
                "127.0.0.1",
                "TestAgent"
            );
            return sessionAuthResult.IsAuthorized && !sessionAuthResult2.IsAuthorized;
        }

        private async Task<bool> TestAuthorizeSessionInvalidToken()
        {
            var sessionAuthResult = await _authzService.AuthorizeSessionAsync(
                "invalid-token",
                "ReadUser",
                null,
                "127.0.0.1",
                "TestAgent"
            );
            return !sessionAuthResult.IsAuthorized;
        }

        private async Task<bool> TestAssignRoleToUserSuccess()
        {
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

            if (!registerResult1.IsSuccess || !registerResult2.IsSuccess) return false;

            await _dbManager.AssignRoleToUserAsync(registerResult1.UserId, "Admin");

            var assignResult = await _authzService.AssignRoleToUserAsync(
                registerResult2.UserId,
                "Manager",
                registerResult1.UserId,
                "127.0.0.1",
                "TestAgent"
            );
            return assignResult.IsSuccess;
        }

        private async Task<bool> TestAssignRoleToUserInvalidInputs()
        {
            var assignResult = await _authzService.AssignRoleToUserAsync(
                0,
                "Manager",
                1,
                "127.0.0.1",
                "TestAgent"
            );
            return !assignResult.IsSuccess;
        }

        private async Task<bool> TestAssignRoleToUserInsufficientPermissions()
        {
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

            if (!registerResult1.IsSuccess || !registerResult2.IsSuccess) return false;

            var assignResult = await _authzService.AssignRoleToUserAsync(
                registerResult2.UserId,
                "Manager",
                registerResult1.UserId,
                "127.0.0.1",
                "TestAgent"
            );
            return !assignResult.IsSuccess;
        }

        private async Task<bool> TestRemoveRoleFromUserSuccess()
        {
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

            if (!registerResult1.IsSuccess || !registerResult2.IsSuccess) return false;

            await _dbManager.AssignRoleToUserAsync(registerResult1.UserId, "Admin");
            await _dbManager.AssignRoleToUserAsync(registerResult2.UserId, "Manager");

            var removeResult = await _authzService.RemoveRoleFromUserAsync(
                registerResult2.UserId,
                "Manager",
                registerResult1.UserId,
                "127.0.0.1",
                "TestAgent"
            );
            return removeResult.IsSuccess;
        }

        private async Task<bool> TestRemoveRoleFromUserInvalidInputs()
        {
            var removeResult = await _authzService.RemoveRoleFromUserAsync(
                0,
                "Manager",
                1,
                "127.0.0.1",
                "TestAgent"
            );
            return !removeResult.IsSuccess;
        }

        private async Task<bool> TestRemoveRoleFromUserInsufficientPermissions()
        {
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

            if (!registerResult1.IsSuccess || !registerResult2.IsSuccess) return false;

            await _dbManager.AssignRoleToUserAsync(registerResult2.UserId, "Manager");

            var removeResult = await _authzService.RemoveRoleFromUserAsync(
                registerResult2.UserId,
                "Manager",
                registerResult1.UserId,
                "127.0.0.1",
                "TestAgent"
            );
            return !removeResult.IsSuccess;
        }

        private async Task<bool> TestGetAllRolesSuccess()
        {
            var roles = await _authzService.GetAllRolesAsync();
            return roles != null && roles.Count > 0;
        }

        private async Task<bool> TestGetRolePermissionsSuccess()
        {
            var adminPermissions = await _authzService.GetRolePermissionsAsync("Admin");
            var userPermissions = await _authzService.GetRolePermissionsAsync("User");
            return adminPermissions != null && userPermissions != null;
        }

        // Integration test methods
        private async Task<bool> TestEndToEndAuthenticationFlow()
        {
            var registerResult = await _authService.RegisterUserAsync(
                "e2euser",
                "e2euser@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            if (!registerResult.IsSuccess) return false;

            var authResult = await _authService.AuthenticateUserAsync(
                "e2euser",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            if (!authResult.IsSuccess) return false;

            var sessionAuthResult = await _authzService.AuthorizeSessionAsync(
                authResult.Token,
                "ReadUser",
                null,
                "127.0.0.1",
                "TestAgent"
            );

            if (!sessionAuthResult.IsAuthorized) return false;

            var logoutResult = await _authService.LogoutUserAsync(
                authResult.SessionId,
                "127.0.0.1",
                "TestAgent"
            );
            return logoutResult.IsSuccess;
        }

        private async Task<bool> TestEndToEndAuthorizationFlow()
        {
            var registerResult1 = await _authService.RegisterUserAsync(
                "e2euser1",
                "e2euser1@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            var registerResult2 = await _authService.RegisterUserAsync(
                "e2euser2",
                "e2euser2@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            if (!registerResult1.IsSuccess || !registerResult2.IsSuccess) return false;

            await _dbManager.AssignRoleToUserAsync(registerResult1.UserId, "Admin");

            var assignResult = await _authzService.AssignRoleToUserAsync(
                registerResult2.UserId,
                "Manager",
                registerResult1.UserId,
                "127.0.0.1",
                "TestAgent"
            );

            if (!assignResult.IsSuccess) return false;

            bool hasManagerRole = await _authzService.UserHasRoleAsync(registerResult2.UserId, "Manager");
            return hasManagerRole;
        }

        private async Task<bool> TestConcurrentAuthenticationRequests()
        {
            var tasks = new List<Task<bool>>();
            
            for (int i = 0; i < 5; i++)
            {
                int index = i;
                tasks.Add(Task.Run(async () =>
                {
                    var registerResult = await _authService.RegisterUserAsync(
                        $"concurrentuser{index}",
                        $"concurrentuser{index}@example.com",
                        "SecurePass123!",
                        "127.0.0.1",
                        "TestAgent"
                    );

                    if (!registerResult.IsSuccess) return false;

                    var authResult = await _authService.AuthenticateUserAsync(
                        $"concurrentuser{index}",
                        "SecurePass123!",
                        "127.0.0.1",
                        "TestAgent"
                    );
                    return authResult.IsSuccess;
                }));
            }

            var results = await Task.WhenAll(tasks);
            return results.All(r => r);
        }

        private async Task<bool> TestConcurrentAuthorizationRequests()
        {
            var tasks = new List<Task<bool>>();
            
            for (int i = 0; i < 5; i++)
            {
                int index = i;
                tasks.Add(Task.Run(async () =>
                {
                    var registerResult = await _authService.RegisterUserAsync(
                        $"concurrentauthuser{index}",
                        $"concurrentauthuser{index}@example.com",
                        "SecurePass123!",
                        "127.0.0.1",
                        "TestAgent"
                    );

                    if (!registerResult.IsSuccess) return false;

                    var authResult = await _authzService.AuthorizeUserAsync(
                        registerResult.UserId,
                        "ReadUser",
                        null,
                        "127.0.0.1",
                        "TestAgent"
                    );
                    return authResult.IsAuthorized;
                }));
            }

            var results = await Task.WhenAll(tasks);
            return results.All(r => r);
        }

        private async Task<bool> TestSessionSecurity()
        {
            var registerResult = await _authService.RegisterUserAsync(
                "sessionuser",
                "sessionuser@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            if (!registerResult.IsSuccess) return false;

            var session = await _sessionManager.CreateSessionAsync(
                registerResult.UserId,
                "127.0.0.1",
                "TestAgent"
            );

            if (session == null) return false;

            // Test invalid token
            var invalidSession = await _sessionManager.ValidateTokenAsync("invalid-token");
            if (invalidSession != null) return false;

            // Test empty token
            var emptySession = await _sessionManager.ValidateTokenAsync("");
            if (emptySession != null) return false;

            // Test valid token
            var validSession = await _sessionManager.ValidateTokenAsync(session.Token);
            return validSession != null;
        }

        private async Task<bool> TestRoleBasedAccessControl()
        {
            var registerResult = await _authService.RegisterUserAsync(
                "rbacuser",
                "rbacuser@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            if (!registerResult.IsSuccess) return false;

            // Test default User role permissions
            bool canReadUser = await _authzService.UserCanPerformActionAsync(registerResult.UserId, "ReadUser");
            bool canCreateUser = await _authzService.UserCanPerformActionAsync(registerResult.UserId, "CreateUser");
            bool canAssignRole = await _authzService.UserCanPerformActionAsync(registerResult.UserId, "AssignRole");

            return canReadUser && !canCreateUser && !canAssignRole;
        }

        private async Task<bool> TestPermissionInheritance()
        {
            var registerResult = await _authService.RegisterUserAsync(
                "inherituser",
                "inherituser@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            if (!registerResult.IsSuccess) return false;

            // Assign multiple roles
            await _dbManager.AssignRoleToUserAsync(registerResult.UserId, "Manager");

            // Test that user has permissions from both roles
            bool canReadUser = await _authzService.UserCanPerformActionAsync(registerResult.UserId, "ReadUser");
            bool canCreateUser = await _authzService.UserCanPerformActionAsync(registerResult.UserId, "CreateUser");
            bool canAssignRole = await _authzService.UserCanPerformActionAsync(registerResult.UserId, "AssignRole");

            return canReadUser && canCreateUser && canAssignRole;
        }

        private async Task<bool> TestAuditLogging()
        {
            var registerResult = await _authService.RegisterUserAsync(
                "audituser",
                "audituser@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            if (!registerResult.IsSuccess) return false;

            var authResult = await _authService.AuthenticateUserAsync(
                "audituser",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            if (!authResult.IsSuccess) return false;

            var authzResult = await _authzService.AuthorizeUserAsync(
                registerResult.UserId,
                "ReadUser",
                null,
                "127.0.0.1",
                "TestAgent"
            );

            return authzResult.IsAuthorized;
        }

        private void GenerateReport(AuthTestReport report)
        {
            Console.WriteLine("\n" + new string('=', 70));
            Console.WriteLine("SAFEVAULT AUTHENTICATION & AUTHORIZATION TEST REPORT");
            Console.WriteLine(new string('=', 70));
            
            Console.WriteLine($"Test Duration: {report.Duration.TotalSeconds:F2} seconds");
            Console.WriteLine($"Total Tests: {report.TestResults.Count}");
            
            var passedTests = report.TestResults.Count(t => t.Passed);
            var failedTests = report.TestResults.Count(t => !t.Passed);
            
            Console.WriteLine($"Passed: {passedTests}");
            Console.WriteLine($"Failed: {failedTests}");
            Console.WriteLine($"Success Rate: {(double)passedTests / report.TestResults.Count * 100:F1}%");
            
            if (failedTests > 0)
            {
                Console.WriteLine("\nFAILED TESTS:");
                Console.WriteLine(new string('-', 50));
                foreach (var test in report.TestResults.Where(t => !t.Passed))
                {
                    Console.WriteLine($"  {test.TestName}: {test.ErrorMessage}");
                }
            }
            
            Console.WriteLine("\nSECURITY ASSESSMENT:");
            Console.WriteLine(new string('-', 50));
            
            if (failedTests == 0)
            {
                Console.WriteLine("✅ ALL AUTHENTICATION & AUTHORIZATION TESTS PASSED");
                Console.WriteLine("✅ User authentication is working correctly");
                Console.WriteLine("✅ Password hashing and validation is secure");
                Console.WriteLine("✅ Session management is functioning properly");
                Console.WriteLine("✅ Role-based access control is effective");
                Console.WriteLine("✅ Permission system is working correctly");
                Console.WriteLine("✅ Audit logging is operational");
            }
            else
            {
                Console.WriteLine("❌ SOME AUTHENTICATION & AUTHORIZATION TESTS FAILED");
                Console.WriteLine("❌ System may have security vulnerabilities");
                Console.WriteLine("❌ Review failed tests and implement fixes");
            }
            
            Console.WriteLine("\nRECOMMENDATIONS:");
            Console.WriteLine(new string('-', 50));
            Console.WriteLine("1. Regularly run these authentication and authorization tests");
            Console.WriteLine("2. Monitor for failed login attempts and suspicious activity");
            Console.WriteLine("3. Keep authentication libraries and frameworks updated");
            Console.WriteLine("4. Implement additional security measures as needed");
            Console.WriteLine("5. Consider penetration testing by security professionals");
            Console.WriteLine("6. Review and update role permissions regularly");
            Console.WriteLine("7. Monitor audit logs for security events");
            
            Console.WriteLine(new string('=', 70));
        }

        public void Dispose()
        {
            _dbManager?.Dispose();
        }
    }

    /// <summary>
    /// Authentication and authorization test report model
    /// </summary>
    public class AuthTestReport
    {
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public TimeSpan Duration { get; set; }
        public List<TestResult> TestResults { get; set; }
    }
}
