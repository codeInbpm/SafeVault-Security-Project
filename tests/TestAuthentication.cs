using NUnit.Framework;
using SafeVault.Services;
using SafeVault.Data;
using System;
using System.Threading.Tasks;
using System.Collections.Generic;

namespace SafeVault.Tests
{
    /// <summary>
    /// Comprehensive test suite for authentication system
    /// Tests password hashing, user authentication, and session management
    /// </summary>
    [TestFixture]
    public class TestAuthentication
    {
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
        }

        [TearDown]
        public void TearDown()
        {
            _dbManager?.Dispose();
        }

        [Test]
        public async Task TestUserRegistration_Success()
        {
            // Test successful user registration
            var result = await _authService.RegisterUserAsync(
                "testuser1",
                "testuser1@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsTrue(result.IsSuccess, "User registration should succeed");
            Assert.IsTrue(result.UserId > 0, "User ID should be positive");
            Assert.AreEqual("User registered successfully", result.Message);
        }

        [Test]
        public async Task TestUserRegistration_DuplicateUsername()
        {
            // Register first user
            await _authService.RegisterUserAsync(
                "duplicateuser",
                "duplicateuser1@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            // Try to register with same username
            var result = await _authService.RegisterUserAsync(
                "duplicateuser",
                "duplicateuser2@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsFalse(result.IsSuccess, "Duplicate username should fail");
            Assert.AreEqual("Username already exists", result.ErrorMessage);
        }

        [Test]
        public async Task TestUserRegistration_DuplicateEmail()
        {
            // Register first user
            await _authService.RegisterUserAsync(
                "user1",
                "duplicate@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            // Try to register with same email
            var result = await _authService.RegisterUserAsync(
                "user2",
                "duplicate@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsFalse(result.IsSuccess, "Duplicate email should fail");
            Assert.AreEqual("Email already exists", result.ErrorMessage);
        }

        [Test]
        public async Task TestUserRegistration_InvalidInputs()
        {
            var invalidInputs = new List<(string username, string email, string password, string expectedError)>
            {
                ("", "test@example.com", "SecurePass123!", "Username, email, and password are required"),
                ("testuser", "", "SecurePass123!", "Username, email, and password are required"),
                ("testuser", "test@example.com", "", "Username, email, and password are required"),
                ("ab", "test@example.com", "SecurePass123!", "Username validation failed"),
                ("testuser", "invalid-email", "SecurePass123!", "Email validation failed"),
                ("testuser", "test@example.com", "weak", "Password validation failed"),
                ("testuser", "test@example.com", "nouppercase123!", "Password validation failed"),
                ("testuser", "test@example.com", "NOLOWERCASE123!", "Password validation failed"),
                ("testuser", "test@example.com", "NoNumbers!", "Password validation failed"),
                ("testuser", "test@example.com", "NoSpecialChars123", "Password validation failed")
            };

            foreach (var (username, email, password, expectedError) in invalidInputs)
            {
                var result = await _authService.RegisterUserAsync(
                    username,
                    email,
                    password,
                    "127.0.0.1",
                    "TestAgent"
                );

                Assert.IsFalse(result.IsSuccess, $"Registration should fail for: {username}, {email}");
                Assert.IsTrue(result.ErrorMessage.Contains(expectedError.Split(':')[0]), 
                    $"Expected error for {username}, {email}: {result.ErrorMessage}");
            }
        }

        [Test]
        public async Task TestUserAuthentication_Success()
        {
            // Register a user first
            var registerResult = await _authService.RegisterUserAsync(
                "authuser",
                "authuser@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsTrue(registerResult.IsSuccess, "User registration should succeed");

            // Authenticate the user
            var authResult = await _authService.AuthenticateUserAsync(
                "authuser",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsTrue(authResult.IsSuccess, "Authentication should succeed");
            Assert.AreEqual(registerResult.UserId, authResult.UserId, "User IDs should match");
            Assert.AreEqual("authuser", authResult.Username, "Usernames should match");
            Assert.AreEqual("authuser@example.com", authResult.Email, "Emails should match");
            Assert.IsNotNull(authResult.Token, "Token should not be null");
            Assert.IsNotNull(authResult.SessionId, "Session ID should not be null");
            Assert.IsTrue(authResult.ExpiresAt > DateTime.UtcNow, "Expiration should be in the future");
        }

        [Test]
        public async Task TestUserAuthentication_InvalidCredentials()
        {
            // Register a user first
            await _authService.RegisterUserAsync(
                "authuser2",
                "authuser2@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            // Test invalid username
            var result1 = await _authService.AuthenticateUserAsync(
                "nonexistentuser",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsFalse(result1.IsSuccess, "Authentication should fail for invalid username");
            Assert.AreEqual("Invalid username or password", result1.ErrorMessage);

            // Test invalid password
            var result2 = await _authService.AuthenticateUserAsync(
                "authuser2",
                "WrongPassword123!",
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsFalse(result2.IsSuccess, "Authentication should fail for invalid password");
            Assert.AreEqual("Invalid username or password", result2.ErrorMessage);
        }

        [Test]
        public async Task TestUserAuthentication_EmptyInputs()
        {
            var emptyInputs = new List<(string username, string password)>
            {
                ("", "SecurePass123!"),
                ("testuser", ""),
                ("", ""),
                (null, "SecurePass123!"),
                ("testuser", null),
                (null, null)
            };

            foreach (var (username, password) in emptyInputs)
            {
                var result = await _authService.AuthenticateUserAsync(
                    username,
                    password,
                    "127.0.0.1",
                    "TestAgent"
                );

                Assert.IsFalse(result.IsSuccess, $"Authentication should fail for empty inputs: {username}, {password}");
                Assert.AreEqual("Username and password are required", result.ErrorMessage);
            }
        }

        [Test]
        public async Task TestUserAuthentication_InvalidUsernameFormat()
        {
            var invalidUsernames = new List<string>
            {
                "ab", // Too short
                "user<script>alert('xss')</script>", // XSS attempt
                "user'; DROP TABLE Users; --", // SQL injection attempt
                "user name", // Contains space
                "user@domain.com", // Contains @
                "user-name", // Contains hyphen
                "user.name", // Contains dot
                "user/name", // Contains slash
                "user\\name", // Contains backslash
                "user<name", // Contains <
                "user>name", // Contains >
                "user&name", // Contains &
                "user\"name", // Contains quote
                "user'name", // Contains apostrophe
                "user;name", // Contains semicolon
                "user:name", // Contains colon
                "user|name", // Contains pipe
                "user*name", // Contains asterisk
                "user?name", // Contains question mark
                "user#name", // Contains hash
                "user%name", // Contains percent
                "user+name", // Contains plus
                "user=name", // Contains equals
                "user!name", // Contains exclamation
                "user$name", // Contains dollar
                "user^name", // Contains caret
                "user~name", // Contains tilde
                "user`name", // Contains backtick
                "user[name", // Contains bracket
                "user]name", // Contains bracket
                "user{name", // Contains brace
                "user}name", // Contains brace
                "user(name", // Contains parenthesis
                "user)name", // Contains parenthesis
                "user,name", // Contains comma
                "user.name", // Contains dot
                "user<name", // Contains less than
                "user>name", // Contains greater than
                "user/name", // Contains forward slash
                "user\\name" // Contains backslash
            };

            foreach (var username in invalidUsernames)
            {
                var result = await _authService.AuthenticateUserAsync(
                    username,
                    "SecurePass123!",
                    "127.0.0.1",
                    "TestAgent"
                );

                Assert.IsFalse(result.IsSuccess, $"Authentication should fail for invalid username: {username}");
                Assert.IsTrue(result.ErrorMessage.Contains("Invalid username format") || 
                             result.ErrorMessage.Contains("Invalid username or password"), 
                    $"Expected validation error for username: {username}");
            }
        }

        [Test]
        public async Task TestPasswordChange_Success()
        {
            // Register a user first
            var registerResult = await _authService.RegisterUserAsync(
                "passuser",
                "passuser@example.com",
                "OldPass123!",
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsTrue(registerResult.IsSuccess, "User registration should succeed");

            // Change password
            var changeResult = await _authService.ChangePasswordAsync(
                registerResult.UserId,
                "OldPass123!",
                "NewPass123!",
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsTrue(changeResult.IsSuccess, "Password change should succeed");
            Assert.AreEqual("Password changed successfully", changeResult.Message);

            // Verify old password no longer works
            var oldAuthResult = await _authService.AuthenticateUserAsync(
                "passuser",
                "OldPass123!",
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsFalse(oldAuthResult.IsSuccess, "Old password should no longer work");

            // Verify new password works
            var newAuthResult = await _authService.AuthenticateUserAsync(
                "passuser",
                "NewPass123!",
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsTrue(newAuthResult.IsSuccess, "New password should work");
        }

        [Test]
        public async Task TestPasswordChange_InvalidCurrentPassword()
        {
            // Register a user first
            var registerResult = await _authService.RegisterUserAsync(
                "passuser2",
                "passuser2@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsTrue(registerResult.IsSuccess, "User registration should succeed");

            // Try to change password with wrong current password
            var changeResult = await _authService.ChangePasswordAsync(
                registerResult.UserId,
                "WrongPass123!",
                "NewPass123!",
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsFalse(changeResult.IsSuccess, "Password change should fail with wrong current password");
            Assert.AreEqual("Current password is incorrect", changeResult.ErrorMessage);
        }

        [Test]
        public async Task TestPasswordChange_InvalidNewPassword()
        {
            // Register a user first
            var registerResult = await _authService.RegisterUserAsync(
                "passuser3",
                "passuser3@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsTrue(registerResult.IsSuccess, "User registration should succeed");

            var invalidNewPasswords = new List<string>
            {
                "", // Empty
                "short", // Too short
                "nouppercase123!", // No uppercase
                "NOLOWERCASE123!", // No lowercase
                "NoNumbers!", // No numbers
                "NoSpecialChars123", // No special chars
                "a".PadRight(129, 'a') + "1A!" // Too long
            };

            foreach (var newPassword in invalidNewPasswords)
            {
                var changeResult = await _authService.ChangePasswordAsync(
                    registerResult.UserId,
                    "SecurePass123!",
                    newPassword,
                    "127.0.0.1",
                    "TestAgent"
                );

                Assert.IsFalse(changeResult.IsSuccess, $"Password change should fail for invalid new password: {newPassword}");
                Assert.IsTrue(changeResult.ErrorMessage.Contains("New password validation failed"), 
                    $"Expected validation error for new password: {newPassword}");
            }
        }

        [Test]
        public async Task TestPasswordChange_EmptyInputs()
        {
            // Register a user first
            var registerResult = await _authService.RegisterUserAsync(
                "passuser4",
                "passuser4@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsTrue(registerResult.IsSuccess, "User registration should succeed");

            var emptyInputs = new List<(string currentPassword, string newPassword)>
            {
                ("", "NewPass123!"),
                ("SecurePass123!", ""),
                ("", ""),
                (null, "NewPass123!"),
                ("SecurePass123!", null),
                (null, null)
            };

            foreach (var (currentPassword, newPassword) in emptyInputs)
            {
                var changeResult = await _authService.ChangePasswordAsync(
                    registerResult.UserId,
                    currentPassword,
                    newPassword,
                    "127.0.0.1",
                    "TestAgent"
                );

                Assert.IsFalse(changeResult.IsSuccess, $"Password change should fail for empty inputs: {currentPassword}, {newPassword}");
                Assert.AreEqual("Current and new passwords are required", changeResult.ErrorMessage);
            }
        }

        [Test]
        public async Task TestUserLogout_Success()
        {
            // Register and authenticate a user first
            var registerResult = await _authService.RegisterUserAsync(
                "logoutuser",
                "logoutuser@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsTrue(registerResult.IsSuccess, "User registration should succeed");

            var authResult = await _authService.AuthenticateUserAsync(
                "logoutuser",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsTrue(authResult.IsSuccess, "Authentication should succeed");

            // Logout the user
            var logoutResult = await _authService.LogoutUserAsync(
                authResult.SessionId,
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsTrue(logoutResult.IsSuccess, "Logout should succeed");
            Assert.AreEqual("Logged out successfully", logoutResult.Message);
        }

        [Test]
        public async Task TestUserLogout_InvalidSession()
        {
            // Try to logout with invalid session ID
            var logoutResult = await _authService.LogoutUserAsync(
                "invalid-session-id",
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsFalse(logoutResult.IsSuccess, "Logout should fail for invalid session");
            Assert.AreEqual("Invalid session", logoutResult.ErrorMessage);
        }

        [Test]
        public async Task TestUserLogout_EmptySessionId()
        {
            // Try to logout with empty session ID
            var logoutResult = await _authService.LogoutUserAsync(
                "",
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsFalse(logoutResult.IsSuccess, "Logout should fail for empty session ID");
            Assert.AreEqual("Session ID is required", logoutResult.ErrorMessage);
        }

        [Test]
        public async Task TestSessionManagement_CreateSession()
        {
            // Register a user first
            var registerResult = await _authService.RegisterUserAsync(
                "sessionuser",
                "sessionuser@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsTrue(registerResult.IsSuccess, "User registration should succeed");

            // Create a session
            var session = await _sessionManager.CreateSessionAsync(
                registerResult.UserId,
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsNotNull(session, "Session should be created");
            Assert.AreEqual(registerResult.UserId, session.UserId, "User IDs should match");
            Assert.IsNotNull(session.SessionId, "Session ID should not be null");
            Assert.IsNotNull(session.Token, "Token should not be null");
            Assert.IsTrue(session.ExpiresAt > DateTime.UtcNow, "Expiration should be in the future");
            Assert.IsTrue(session.IsActive, "Session should be active");
        }

        [Test]
        public async Task TestSessionManagement_ValidateSession()
        {
            // Register a user first
            var registerResult = await _authService.RegisterUserAsync(
                "sessionuser2",
                "sessionuser2@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsTrue(registerResult.IsSuccess, "User registration should succeed");

            // Create a session
            var session = await _sessionManager.CreateSessionAsync(
                registerResult.UserId,
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsNotNull(session, "Session should be created");

            // Validate the session
            var validatedSession = await _sessionManager.ValidateTokenAsync(session.Token);

            Assert.IsNotNull(validatedSession, "Session should be valid");
            Assert.AreEqual(session.SessionId, validatedSession.SessionId, "Session IDs should match");
            Assert.AreEqual(session.UserId, validatedSession.UserId, "User IDs should match");
        }

        [Test]
        public async Task TestSessionManagement_InvalidToken()
        {
            // Try to validate an invalid token
            var validatedSession = await _sessionManager.ValidateTokenAsync("invalid-token");

            Assert.IsNull(validatedSession, "Invalid token should return null");
        }

        [Test]
        public async Task TestSessionManagement_EmptyToken()
        {
            // Try to validate an empty token
            var validatedSession = await _sessionManager.ValidateTokenAsync("");

            Assert.IsNull(validatedSession, "Empty token should return null");
        }

        [Test]
        public async Task TestSessionManagement_InvalidateSession()
        {
            // Register a user first
            var registerResult = await _authService.RegisterUserAsync(
                "sessionuser3",
                "sessionuser3@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsTrue(registerResult.IsSuccess, "User registration should succeed");

            // Create a session
            var session = await _sessionManager.CreateSessionAsync(
                registerResult.UserId,
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsNotNull(session, "Session should be created");

            // Invalidate the session
            await _sessionManager.InvalidateSessionAsync(session.SessionId);

            // Try to validate the invalidated session
            var validatedSession = await _sessionManager.ValidateTokenAsync(session.Token);

            Assert.IsNull(validatedSession, "Invalidated session should return null");
        }

        [Test]
        public async Task TestSessionManagement_RefreshSession()
        {
            // Register a user first
            var registerResult = await _authService.RegisterUserAsync(
                "sessionuser4",
                "sessionuser4@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsTrue(registerResult.IsSuccess, "User registration should succeed");

            // Create a session
            var session = await _sessionManager.CreateSessionAsync(
                registerResult.UserId,
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsNotNull(session, "Session should be created");

            // Refresh the session
            var refreshedSession = await _sessionManager.RefreshSessionAsync(session.SessionId);

            Assert.IsNotNull(refreshedSession, "Refreshed session should not be null");
            Assert.AreEqual(session.SessionId, refreshedSession.SessionId, "Session IDs should match");
            Assert.AreEqual(session.UserId, refreshedSession.UserId, "User IDs should match");
            Assert.IsTrue(refreshedSession.ExpiresAt > session.ExpiresAt, "Refreshed session should have later expiration");
        }

        [Test]
        public async Task TestSessionManagement_InvalidateAllUserSessions()
        {
            // Register a user first
            var registerResult = await _authService.RegisterUserAsync(
                "sessionuser5",
                "sessionuser5@example.com",
                "SecurePass123!",
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsTrue(registerResult.IsSuccess, "User registration should succeed");

            // Create multiple sessions
            var session1 = await _sessionManager.CreateSessionAsync(
                registerResult.UserId,
                "127.0.0.1",
                "TestAgent"
            );

            var session2 = await _sessionManager.CreateSessionAsync(
                registerResult.UserId,
                "127.0.0.1",
                "TestAgent"
            );

            Assert.IsNotNull(session1, "First session should be created");
            Assert.IsNotNull(session2, "Second session should be created");

            // Invalidate all user sessions
            await _sessionManager.InvalidateAllUserSessionsAsync(registerResult.UserId);

            // Try to validate both sessions
            var validatedSession1 = await _sessionManager.ValidateTokenAsync(session1.Token);
            var validatedSession2 = await _sessionManager.ValidateTokenAsync(session2.Token);

            Assert.IsNull(validatedSession1, "First session should be invalidated");
            Assert.IsNull(validatedSession2, "Second session should be invalidated");
        }

        [Test]
        public async Task TestConcurrentAuthentication()
        {
            // Test concurrent authentication attempts
            var tasks = new List<Task<AuthenticationResult>>();
            
            for (int i = 0; i < 10; i++)
            {
                int index = i;
                tasks.Add(Task.Run(async () =>
                {
                    // Register a user for each task
                    var registerResult = await _authService.RegisterUserAsync(
                        $"concurrentuser{index}",
                        $"concurrentuser{index}@example.com",
                        "SecurePass123!",
                        "127.0.0.1",
                        "TestAgent"
                    );

                    if (registerResult.IsSuccess)
                    {
                        // Authenticate the user
                        return await _authService.AuthenticateUserAsync(
                            $"concurrentuser{index}",
                            "SecurePass123!",
                            "127.0.0.1",
                            "TestAgent"
                        );
                    }
                    else
                    {
                        return new AuthenticationResult { IsSuccess = false };
                    }
                }));
            }

            var results = await Task.WhenAll(tasks);
            
            // Check that all authentications succeeded
            foreach (var result in results)
            {
                Assert.IsTrue(result.IsSuccess, "Concurrent authentication should succeed");
            }
        }

        [Test]
        public async Task TestErrorHandling()
        {
            // Test error handling for various scenarios
            try
            {
                // Test with null parameters
                var result = await _authService.RegisterUserAsync(null, null, null, null, null);
                Assert.IsFalse(result.IsSuccess, "Registration should fail with null parameters");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex.Message.Contains("null") || ex.Message.Contains("Null"), 
                    $"Expected null parameter error: {ex.Message}");
            }

            try
            {
                // Test with empty parameters
                var result = await _authService.RegisterUserAsync("", "", "", "", "");
                Assert.IsFalse(result.IsSuccess, "Registration should fail with empty parameters");
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex.Message.Contains("required") || ex.Message.Contains("empty"), 
                    $"Expected empty parameter error: {ex.Message}");
            }
        }
    }
}
