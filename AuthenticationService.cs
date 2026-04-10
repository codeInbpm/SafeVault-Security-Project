using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using SafeVault.Data;
using SafeVault.Security;
using System.Collections.Generic;
using System.Linq;

namespace SafeVault.Services
{
    /// <summary>
    /// Secure authentication service with password hashing and user verification
    /// </summary>
    public class AuthenticationService
    {
        private readonly SecureDatabaseManager _dbManager;
        private readonly SessionManager _sessionManager;
        private readonly AuditLogger _auditLogger;

        public AuthenticationService(SecureDatabaseManager dbManager, SessionManager sessionManager, AuditLogger auditLogger)
        {
            _dbManager = dbManager ?? throw new ArgumentNullException(nameof(dbManager));
            _sessionManager = sessionManager ?? throw new ArgumentNullException(nameof(sessionManager));
            _auditLogger = auditLogger ?? throw new ArgumentNullException(nameof(auditLogger));
        }

        /// <summary>
        /// Authenticates a user with username and password
        /// </summary>
        /// <param name="username">Username</param>
        /// <param name="password">Plain text password</param>
        /// <param name="ipAddress">Client IP address</param>
        /// <param name="userAgent">Client user agent</param>
        /// <returns>Authentication result</returns>
        public async Task<AuthenticationResult> AuthenticateUserAsync(string username, string password, string ipAddress, string userAgent)
        {
            try
            {
                // Validate input
                if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
                {
                    await _auditLogger.LogAsync(null, "AUTHENTICATION_FAILED", "Empty username or password", ipAddress, userAgent);
                    return new AuthenticationResult
                    {
                        IsSuccess = false,
                        ErrorMessage = "Username and password are required"
                    };
                }

                // Validate username format
                var usernameValidation = SecureInputValidator.ValidateUsername(username);
                if (!usernameValidation.IsValid)
                {
                    await _auditLogger.LogAsync(null, "AUTHENTICATION_FAILED", $"Invalid username format: {username}", ipAddress, userAgent);
                    return new AuthenticationResult
                    {
                        IsSuccess = false,
                        ErrorMessage = "Invalid username format"
                    };
                }

                // Get user from database
                var user = await _dbManager.GetUserByUsernameAsync(usernameValidation.SanitizedValue);
                if (user == null)
                {
                    await _auditLogger.LogAsync(null, "AUTHENTICATION_FAILED", $"User not found: {username}", ipAddress, userAgent);
                    return new AuthenticationResult
                    {
                        IsSuccess = false,
                        ErrorMessage = "Invalid username or password"
                    };
                }

                // Check if account is locked
                if (user.IsLocked)
                {
                    await _auditLogger.LogAsync(user.UserId, "AUTHENTICATION_BLOCKED", "Account is locked", ipAddress, userAgent);
                    return new AuthenticationResult
                    {
                        IsSuccess = false,
                        ErrorMessage = "Account is locked. Please contact administrator."
                    };
                }

                // Check if account is active
                if (!user.IsActive)
                {
                    await _auditLogger.LogAsync(user.UserId, "AUTHENTICATION_BLOCKED", "Account is inactive", ipAddress, userAgent);
                    return new AuthenticationResult
                    {
                        IsSuccess = false,
                        ErrorMessage = "Account is inactive. Please contact administrator."
                    };
                }

                // Verify password
                bool isPasswordValid = await VerifyPasswordAsync(password, user.PasswordHash, user.Salt);
                if (!isPasswordValid)
                {
                    // Increment failed login attempts
                    await _dbManager.IncrementFailedLoginAttemptsAsync(user.UserId);
                    
                    await _auditLogger.LogAsync(user.UserId, "AUTHENTICATION_FAILED", "Invalid password", ipAddress, userAgent);
                    return new AuthenticationResult
                    {
                        IsSuccess = false,
                        ErrorMessage = "Invalid username or password"
                    };
                }

                // Reset failed login attempts on successful authentication
                await _dbManager.ResetFailedLoginAttemptsAsync(user.UserId);

                // Create session
                var session = await _sessionManager.CreateSessionAsync(user.UserId, ipAddress, userAgent);

                // Update last login
                await _dbManager.UpdateLastLoginAsync(user.UserId);

                await _auditLogger.LogAsync(user.UserId, "AUTHENTICATION_SUCCESS", "User authenticated successfully", ipAddress, userAgent);

                return new AuthenticationResult
                {
                    IsSuccess = true,
                    UserId = user.UserId,
                    Username = user.Username,
                    Email = user.Email,
                    Roles = user.Roles,
                    SessionId = session.SessionId,
                    Token = session.Token,
                    ExpiresAt = session.ExpiresAt
                };
            }
            catch (Exception ex)
            {
                await _auditLogger.LogAsync(null, "AUTHENTICATION_ERROR", $"Authentication error: {ex.Message}", ipAddress, userAgent);
                return new AuthenticationResult
                {
                    IsSuccess = false,
                    ErrorMessage = "An error occurred during authentication"
                };
            }
        }

        /// <summary>
        /// Verifies a password against its hash and salt
        /// </summary>
        /// <param name="password">Plain text password</param>
        /// <param name="hash">Stored password hash</param>
        /// <param name="salt">Stored password salt</param>
        /// <returns>True if password is valid</returns>
        private async Task<bool> VerifyPasswordAsync(string password, string hash, string salt)
        {
            try
            {
                // Hash the provided password with the stored salt
                string computedHash = SecureInputValidator.HashPassword(password, salt);
                
                // Compare hashes using constant-time comparison to prevent timing attacks
                return SecureCompare(computedHash, hash);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Constant-time string comparison to prevent timing attacks
        /// </summary>
        /// <param name="a">First string</param>
        /// <param name="b">Second string</param>
        /// <returns>True if strings are equal</returns>
        private bool SecureCompare(string a, string b)
        {
            if (a == null || b == null || a.Length != b.Length)
                return false;

            int result = 0;
            for (int i = 0; i < a.Length; i++)
            {
                result |= a[i] ^ b[i];
            }
            return result == 0;
        }

        /// <summary>
        /// Registers a new user with secure password hashing
        /// </summary>
        /// <param name="username">Username</param>
        /// <param name="email">Email address</param>
        /// <param name="password">Plain text password</param>
        /// <param name="ipAddress">Client IP address</param>
        /// <param name="userAgent">Client user agent</param>
        /// <returns>Registration result</returns>
        public async Task<RegistrationResult> RegisterUserAsync(string username, string email, string password, string ipAddress, string userAgent)
        {
            try
            {
                // Validate input
                if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
                {
                    await _auditLogger.LogAsync(null, "REGISTRATION_FAILED", "Empty required fields", ipAddress, userAgent);
                    return new RegistrationResult
                    {
                        IsSuccess = false,
                        ErrorMessage = "Username, email, and password are required"
                    };
                }

                // Validate username
                var usernameValidation = SecureInputValidator.ValidateUsername(username);
                if (!usernameValidation.IsValid)
                {
                    await _auditLogger.LogAsync(null, "REGISTRATION_FAILED", $"Invalid username: {usernameValidation.ErrorMessage}", ipAddress, userAgent);
                    return new RegistrationResult
                    {
                        IsSuccess = false,
                        ErrorMessage = $"Username validation failed: {usernameValidation.ErrorMessage}"
                    };
                }

                // Validate email
                var emailValidation = SecureInputValidator.ValidateEmail(email);
                if (!emailValidation.IsValid)
                {
                    await _auditLogger.LogAsync(null, "REGISTRATION_FAILED", $"Invalid email: {emailValidation.ErrorMessage}", ipAddress, userAgent);
                    return new RegistrationResult
                    {
                        IsSuccess = false,
                        ErrorMessage = $"Email validation failed: {emailValidation.ErrorMessage}"
                    };
                }

                // Validate password
                var passwordValidation = SecureInputValidator.ValidatePassword(password);
                if (!passwordValidation.IsValid)
                {
                    await _auditLogger.LogAsync(null, "REGISTRATION_FAILED", $"Invalid password: {passwordValidation.ErrorMessage}", ipAddress, userAgent);
                    return new RegistrationResult
                    {
                        IsSuccess = false,
                        ErrorMessage = $"Password validation failed: {passwordValidation.ErrorMessage}"
                    };
                }

                // Check if username already exists
                var existingUser = await _dbManager.GetUserByUsernameAsync(usernameValidation.SanitizedValue);
                if (existingUser != null)
                {
                    await _auditLogger.LogAsync(null, "REGISTRATION_FAILED", $"Username already exists: {username}", ipAddress, userAgent);
                    return new RegistrationResult
                    {
                        IsSuccess = false,
                        ErrorMessage = "Username already exists"
                    };
                }

                // Check if email already exists
                var existingEmail = await _dbManager.GetUserByEmailAsync(emailValidation.SanitizedValue);
                if (existingEmail != null)
                {
                    await _auditLogger.LogAsync(null, "REGISTRATION_FAILED", $"Email already exists: {email}", ipAddress, userAgent);
                    return new RegistrationResult
                    {
                        IsSuccess = false,
                        ErrorMessage = "Email already exists"
                    };
                }

                // Generate salt and hash password
                string salt = SecureInputValidator.GenerateSalt();
                string passwordHash = SecureInputValidator.HashPassword(password, salt);

                // Create user
                int userId = await _dbManager.CreateUserAsync(
                    usernameValidation.SanitizedValue,
                    emailValidation.SanitizedValue,
                    passwordHash,
                    salt,
                    ipAddress,
                    userAgent
                );

                if (userId > 0)
                {
                    // Assign default role
                    await _dbManager.AssignRoleToUserAsync(userId, "User");

                    await _auditLogger.LogAsync(userId, "REGISTRATION_SUCCESS", "User registered successfully", ipAddress, userAgent);

                    return new RegistrationResult
                    {
                        IsSuccess = true,
                        UserId = userId,
                        Message = "User registered successfully"
                    };
                }
                else
                {
                    await _auditLogger.LogAsync(null, "REGISTRATION_FAILED", "Failed to create user in database", ipAddress, userAgent);
                    return new RegistrationResult
                    {
                        IsSuccess = false,
                        ErrorMessage = "Failed to create user"
                    };
                }
            }
            catch (Exception ex)
            {
                await _auditLogger.LogAsync(null, "REGISTRATION_ERROR", $"Registration error: {ex.Message}", ipAddress, userAgent);
                return new RegistrationResult
                {
                    IsSuccess = false,
                    ErrorMessage = "An error occurred during registration"
                };
            }
        }

        /// <summary>
        /// Logs out a user and invalidates their session
        /// </summary>
        /// <param name="sessionId">Session ID</param>
        /// <param name="ipAddress">Client IP address</param>
        /// <param name="userAgent">Client user agent</param>
        /// <returns>Logout result</returns>
        public async Task<LogoutResult> LogoutUserAsync(string sessionId, string ipAddress, string userAgent)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(sessionId))
                {
                    return new LogoutResult
                    {
                        IsSuccess = false,
                        ErrorMessage = "Session ID is required"
                    };
                }

                // Get session information
                var session = await _sessionManager.GetSessionAsync(sessionId);
                if (session == null)
                {
                    return new LogoutResult
                    {
                        IsSuccess = false,
                        ErrorMessage = "Invalid session"
                    };
                }

                // Invalidate session
                await _sessionManager.InvalidateSessionAsync(sessionId);

                await _auditLogger.LogAsync(session.UserId, "LOGOUT_SUCCESS", "User logged out successfully", ipAddress, userAgent);

                return new LogoutResult
                {
                    IsSuccess = true,
                    Message = "Logged out successfully"
                };
            }
            catch (Exception ex)
            {
                await _auditLogger.LogAsync(null, "LOGOUT_ERROR", $"Logout error: {ex.Message}", ipAddress, userAgent);
                return new LogoutResult
                {
                    IsSuccess = false,
                    ErrorMessage = "An error occurred during logout"
                };
            }
        }

        /// <summary>
        /// Changes a user's password
        /// </summary>
        /// <param name="userId">User ID</param>
        /// <param name="currentPassword">Current password</param>
        /// <param name="newPassword">New password</param>
        /// <param name="ipAddress">Client IP address</param>
        /// <param name="userAgent">Client user agent</param>
        /// <returns>Password change result</returns>
        public async Task<PasswordChangeResult> ChangePasswordAsync(int userId, string currentPassword, string newPassword, string ipAddress, string userAgent)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(currentPassword) || string.IsNullOrWhiteSpace(newPassword))
                {
                    await _auditLogger.LogAsync(userId, "PASSWORD_CHANGE_FAILED", "Empty password fields", ipAddress, userAgent);
                    return new PasswordChangeResult
                    {
                        IsSuccess = false,
                        ErrorMessage = "Current and new passwords are required"
                    };
                }

                // Get user
                var user = await _dbManager.GetUserByIdAsync(userId);
                if (user == null)
                {
                    await _auditLogger.LogAsync(userId, "PASSWORD_CHANGE_FAILED", "User not found", ipAddress, userAgent);
                    return new PasswordChangeResult
                    {
                        IsSuccess = false,
                        ErrorMessage = "User not found"
                    };
                }

                // Verify current password
                bool isCurrentPasswordValid = await VerifyPasswordAsync(currentPassword, user.PasswordHash, user.Salt);
                if (!isCurrentPasswordValid)
                {
                    await _auditLogger.LogAsync(userId, "PASSWORD_CHANGE_FAILED", "Invalid current password", ipAddress, userAgent);
                    return new PasswordChangeResult
                    {
                        IsSuccess = false,
                        ErrorMessage = "Current password is incorrect"
                    };
                }

                // Validate new password
                var passwordValidation = SecureInputValidator.ValidatePassword(newPassword);
                if (!passwordValidation.IsValid)
                {
                    await _auditLogger.LogAsync(userId, "PASSWORD_CHANGE_FAILED", $"Invalid new password: {passwordValidation.ErrorMessage}", ipAddress, userAgent);
                    return new PasswordChangeResult
                    {
                        IsSuccess = false,
                        ErrorMessage = $"New password validation failed: {passwordValidation.ErrorMessage}"
                    };
                }

                // Generate new salt and hash
                string newSalt = SecureInputValidator.GenerateSalt();
                string newPasswordHash = SecureInputValidator.HashPassword(newPassword, newSalt);

                // Update password
                await _dbManager.UpdateUserPasswordAsync(userId, newPasswordHash, newSalt);

                // Invalidate all sessions for security
                await _sessionManager.InvalidateAllUserSessionsAsync(userId);

                await _auditLogger.LogAsync(userId, "PASSWORD_CHANGE_SUCCESS", "Password changed successfully", ipAddress, userAgent);

                return new PasswordChangeResult
                {
                    IsSuccess = true,
                    Message = "Password changed successfully"
                };
            }
            catch (Exception ex)
            {
                await _auditLogger.LogAsync(userId, "PASSWORD_CHANGE_ERROR", $"Password change error: {ex.Message}", ipAddress, userAgent);
                return new PasswordChangeResult
                {
                    IsSuccess = false,
                    ErrorMessage = "An error occurred while changing password"
                };
            }
        }
    }

    /// <summary>
    /// Authentication result model
    /// </summary>
    public class AuthenticationResult
    {
        public bool IsSuccess { get; set; }
        public int UserId { get; set; }
        public string Username { get; set; }
        public string Email { get; set; }
        public List<string> Roles { get; set; }
        public string SessionId { get; set; }
        public string Token { get; set; }
        public DateTime ExpiresAt { get; set; }
        public string ErrorMessage { get; set; }
    }

    /// <summary>
    /// Registration result model
    /// </summary>
    public class RegistrationResult
    {
        public bool IsSuccess { get; set; }
        public int UserId { get; set; }
        public string Message { get; set; }
        public string ErrorMessage { get; set; }
    }

    /// <summary>
    /// Logout result model
    /// </summary>
    public class LogoutResult
    {
        public bool IsSuccess { get; set; }
        public string Message { get; set; }
        public string ErrorMessage { get; set; }
    }

    /// <summary>
    /// Password change result model
    /// </summary>
    public class PasswordChangeResult
    {
        public bool IsSuccess { get; set; }
        public string Message { get; set; }
        public string ErrorMessage { get; set; }
    }
}
