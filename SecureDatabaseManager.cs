using System;
using System.Data;
using System.Data.SqlClient;
using System.Collections.Generic;
using System.Threading.Tasks;
using SafeVault.Security;

namespace SafeVault.Data
{
    /// <summary>
    /// Secure database manager with parameterized queries to prevent SQL injection
    /// </summary>
    public class SecureDatabaseManager : IDisposable
    {
        private readonly string _connectionString;
        private SqlConnection _connection;
        private bool _disposed = false;

        public SecureDatabaseManager(string connectionString)
        {
            _connectionString = connectionString ?? throw new ArgumentNullException(nameof(connectionString));
        }

        /// <summary>
        /// Creates a new user with secure parameterized query
        /// </summary>
        /// <param name="username">Validated username</param>
        /// <param name="email">Validated email</param>
        /// <param name="passwordHash">Hashed password</param>
        /// <param name="salt">Password salt</param>
        /// <param name="ipAddress">Client IP address</param>
        /// <param name="userAgent">Client user agent</param>
        /// <returns>User ID if successful, -1 if failed</returns>
        public async Task<int> CreateUserAsync(string username, string email, string passwordHash, string salt, string ipAddress, string userAgent)
        {
            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(email) || 
                string.IsNullOrEmpty(passwordHash) || string.IsNullOrEmpty(salt))
            {
                throw new ArgumentException("All parameters must be provided and non-empty");
            }

            try
            {
                using (var connection = new SqlConnection(_connectionString))
                {
                    await connection.OpenAsync();
                    
                    using (var command = new SqlCommand("CreateUser", connection))
                    {
                        command.CommandType = CommandType.StoredProcedure;
                        
                        // Use parameters to prevent SQL injection
                        command.Parameters.AddWithValue("@p_username", username);
                        command.Parameters.AddWithValue("@p_email", email);
                        command.Parameters.AddWithValue("@p_password_hash", passwordHash);
                        command.Parameters.AddWithValue("@p_salt", salt);
                        command.Parameters.AddWithValue("@p_ip_address", ipAddress ?? string.Empty);
                        command.Parameters.AddWithValue("@p_user_agent", userAgent ?? string.Empty);
                        
                        var result = await command.ExecuteScalarAsync();
                        return Convert.ToInt32(result);
                    }
                }
            }
            catch (SqlException ex)
            {
                // Log the error (in production, use proper logging)
                Console.WriteLine($"Database error creating user: {ex.Message}");
                
                // Handle specific SQL errors
                if (ex.Number == 2627) // Unique constraint violation
                {
                    throw new InvalidOperationException("Username or email already exists");
                }
                
                throw new InvalidOperationException("Failed to create user");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Unexpected error creating user: {ex.Message}");
                throw new InvalidOperationException("An unexpected error occurred");
            }
        }

        /// <summary>
        /// Authenticates a user with secure parameterized query
        /// </summary>
        /// <param name="username">Username</param>
        /// <param name="passwordHash">Hashed password</param>
        /// <param name="ipAddress">Client IP address</param>
        /// <param name="userAgent">Client user agent</param>
        /// <returns>Authentication result</returns>
        public async Task<AuthenticationResult> AuthenticateUserAsync(string username, string passwordHash, string ipAddress, string userAgent)
        {
            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(passwordHash))
            {
                return new AuthenticationResult { IsSuccess = false, ErrorMessage = "Username and password are required" };
            }

            try
            {
                using (var connection = new SqlConnection(_connectionString))
                {
                    await connection.OpenAsync();
                    
                    using (var command = new SqlCommand("AuthenticateUser", connection))
                    {
                        command.CommandType = CommandType.StoredProcedure;
                        
                        // Use parameters to prevent SQL injection
                        command.Parameters.AddWithValue("@p_username", username);
                        command.Parameters.AddWithValue("@p_password_hash", passwordHash);
                        command.Parameters.AddWithValue("@p_ip_address", ipAddress ?? string.Empty);
                        command.Parameters.AddWithValue("@p_user_agent", userAgent ?? string.Empty);
                        
                        // Add output parameters
                        var userIdParam = new SqlParameter("@p_user_id", SqlDbType.Int) { Direction = ParameterDirection.Output };
                        var successParam = new SqlParameter("@p_success", SqlDbType.Bit) { Direction = ParameterDirection.Output };
                        
                        command.Parameters.Add(userIdParam);
                        command.Parameters.Add(successParam);
                        
                        await command.ExecuteNonQueryAsync();
                        
                        bool isSuccess = Convert.ToBoolean(successParam.Value);
                        int userId = isSuccess ? Convert.ToInt32(userIdParam.Value) : -1;
                        
                        return new AuthenticationResult
                        {
                            IsSuccess = isSuccess,
                            UserId = userId,
                            ErrorMessage = isSuccess ? null : "Invalid username or password"
                        };
                    }
                }
            }
            catch (SqlException ex)
            {
                Console.WriteLine($"Database error during authentication: {ex.Message}");
                return new AuthenticationResult { IsSuccess = false, ErrorMessage = "Authentication failed" };
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Unexpected error during authentication: {ex.Message}");
                return new AuthenticationResult { IsSuccess = false, ErrorMessage = "An unexpected error occurred" };
            }
        }

        /// <summary>
        /// Retrieves user information by ID with secure parameterized query
        /// </summary>
        /// <param name="userId">User ID</param>
        /// <returns>User information or null if not found</returns>
        public async Task<UserInfo> GetUserByIdAsync(int userId)
        {
            if (userId <= 0)
            {
                throw new ArgumentException("User ID must be positive");
            }

            try
            {
                using (var connection = new SqlConnection(_connectionString))
                {
                    await connection.OpenAsync();
                    
                    // Use parameterized query to prevent SQL injection
                    string query = @"
                        SELECT UserID, Username, Email, CreatedAt, LastLogin, IsActive
                        FROM Users 
                        WHERE UserID = @userId AND IsActive = 1";
                    
                    using (var command = new SqlCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@userId", userId);
                        
                        using (var reader = await command.ExecuteReaderAsync())
                        {
                            if (await reader.ReadAsync())
                            {
                                return new UserInfo
                                {
                                    UserId = reader.GetInt32("UserID"),
                                    Username = reader.GetString("Username"),
                                    Email = reader.GetString("Email"),
                                    CreatedAt = reader.GetDateTime("CreatedAt"),
                                    LastLogin = reader.IsDBNull("LastLogin") ? (DateTime?)null : reader.GetDateTime("LastLogin"),
                                    IsActive = reader.GetBoolean("IsActive")
                                };
                            }
                        }
                    }
                }
            }
            catch (SqlException ex)
            {
                Console.WriteLine($"Database error retrieving user: {ex.Message}");
                throw new InvalidOperationException("Failed to retrieve user information");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Unexpected error retrieving user: {ex.Message}");
                throw new InvalidOperationException("An unexpected error occurred");
            }

            return null;
        }

        /// <summary>
        /// Searches users with secure parameterized query
        /// </summary>
        /// <param name="searchTerm">Search term (will be validated and sanitized)</param>
        /// <param name="limit">Maximum number of results</param>
        /// <returns>List of matching users</returns>
        public async Task<List<UserInfo>> SearchUsersAsync(string searchTerm, int limit = 50)
        {
            if (string.IsNullOrWhiteSpace(searchTerm))
            {
                return new List<UserInfo>();
            }

            // Validate and sanitize search term
            var validationResult = SecureInputValidator.ValidateTextInput(searchTerm, 100);
            if (!validationResult.IsValid)
            {
                throw new ArgumentException("Invalid search term");
            }

            var sanitizedSearchTerm = validationResult.SanitizedValue;

            try
            {
                using (var connection = new SqlConnection(_connectionString))
                {
                    await connection.OpenAsync();
                    
                    // Use parameterized query with LIKE for search
                    string query = @"
                        SELECT TOP (@limit) UserID, Username, Email, CreatedAt, LastLogin, IsActive
                        FROM Users 
                        WHERE (Username LIKE @searchTerm OR Email LIKE @searchTerm) 
                        AND IsActive = 1
                        ORDER BY Username";
                    
                    using (var command = new SqlCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@searchTerm", $"%{sanitizedSearchTerm}%");
                        command.Parameters.AddWithValue("@limit", limit);
                        
                        var users = new List<UserInfo>();
                        
                        using (var reader = await command.ExecuteReaderAsync())
                        {
                            while (await reader.ReadAsync())
                            {
                                users.Add(new UserInfo
                                {
                                    UserId = reader.GetInt32("UserID"),
                                    Username = reader.GetString("Username"),
                                    Email = reader.GetString("Email"),
                                    CreatedAt = reader.GetDateTime("CreatedAt"),
                                    LastLogin = reader.IsDBNull("LastLogin") ? (DateTime?)null : reader.GetDateTime("LastLogin"),
                                    IsActive = reader.GetBoolean("IsActive")
                                });
                            }
                        }
                        
                        return users;
                    }
                }
            }
            catch (SqlException ex)
            {
                Console.WriteLine($"Database error searching users: {ex.Message}");
                throw new InvalidOperationException("Failed to search users");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Unexpected error searching users: {ex.Message}");
                throw new InvalidOperationException("An unexpected error occurred");
            }
        }

        /// <summary>
        /// Logs an audit event with secure parameterized query
        /// </summary>
        /// <param name="userId">User ID (nullable)</param>
        /// <param name="action">Action performed</param>
        /// <param name="details">Action details</param>
        /// <param name="ipAddress">Client IP address</param>
        /// <param name="userAgent">Client user agent</param>
        public async Task LogAuditEventAsync(int? userId, string action, string details, string ipAddress, string userAgent)
        {
            if (string.IsNullOrEmpty(action))
            {
                throw new ArgumentException("Action cannot be null or empty");
            }

            try
            {
                using (var connection = new SqlConnection(_connectionString))
                {
                    await connection.OpenAsync();
                    
                    string query = @"
                        INSERT INTO AuditLog (UserID, Action, Details, IPAddress, UserAgent)
                        VALUES (@userId, @action, @details, @ipAddress, @userAgent)";
                    
                    using (var command = new SqlCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@userId", userId.HasValue ? (object)userId.Value : DBNull.Value);
                        command.Parameters.AddWithValue("@action", action);
                        command.Parameters.AddWithValue("@details", details ?? string.Empty);
                        command.Parameters.AddWithValue("@ipAddress", ipAddress ?? string.Empty);
                        command.Parameters.AddWithValue("@userAgent", userAgent ?? string.Empty);
                        
                        await command.ExecuteNonQueryAsync();
                    }
                }
            }
            catch (SqlException ex)
            {
                Console.WriteLine($"Database error logging audit event: {ex.Message}");
                // Don't throw here as audit logging failure shouldn't break the main operation
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Unexpected error logging audit event: {ex.Message}");
                // Don't throw here as audit logging failure shouldn't break the main operation
            }
        }

        /// <summary>
        /// Gets user by username
        /// </summary>
        /// <param name="username">Username</param>
        /// <returns>User information or null if not found</returns>
        public async Task<UserInfo> GetUserByUsernameAsync(string username)
        {
            if (string.IsNullOrWhiteSpace(username))
                return null;

            try
            {
                using (var connection = new SqlConnection(_connectionString))
                {
                    await connection.OpenAsync();
                    
                    string query = @"
                        SELECT u.UserID, u.Username, u.Email, u.PasswordHash, u.Salt, 
                               u.CreatedAt, u.LastLogin, u.IsActive, u.FailedLoginAttempts, u.AccountLockedUntil,
                               CASE WHEN u.AccountLockedUntil > NOW() THEN TRUE ELSE FALSE END as IsLocked
                        FROM Users u 
                        WHERE u.Username = @username AND u.IsActive = 1";
                    
                    using (var command = new SqlCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@username", username);
                        
                        using (var reader = await command.ExecuteReaderAsync())
                        {
                            if (await reader.ReadAsync())
                            {
                                var user = new UserInfo
                                {
                                    UserId = reader.GetInt32("UserID"),
                                    Username = reader.GetString("Username"),
                                    Email = reader.GetString("Email"),
                                    PasswordHash = reader.GetString("PasswordHash"),
                                    Salt = reader.GetString("Salt"),
                                    CreatedAt = reader.GetDateTime("CreatedAt"),
                                    LastLogin = reader.IsDBNull("LastLogin") ? (DateTime?)null : reader.GetDateTime("LastLogin"),
                                    IsActive = reader.GetBoolean("IsActive"),
                                    FailedLoginAttempts = reader.GetInt32("FailedLoginAttempts"),
                                    AccountLockedUntil = reader.IsDBNull("AccountLockedUntil") ? (DateTime?)null : reader.GetDateTime("AccountLockedUntil"),
                                    IsLocked = reader.GetBoolean("IsLocked")
                                };

                                // Get user roles
                                user.Roles = await GetUserRolesAsync(user.UserId);
                                
                                return user;
                            }
                        }
                    }
                }
            }
            catch
            {
                return null;
            }

            return null;
        }

        /// <summary>
        /// Gets user by email
        /// </summary>
        /// <param name="email">Email address</param>
        /// <returns>User information or null if not found</returns>
        public async Task<UserInfo> GetUserByEmailAsync(string email)
        {
            if (string.IsNullOrWhiteSpace(email))
                return null;

            try
            {
                using (var connection = new SqlConnection(_connectionString))
                {
                    await connection.OpenAsync();
                    
                    string query = @"
                        SELECT u.UserID, u.Username, u.Email, u.PasswordHash, u.Salt, 
                               u.CreatedAt, u.LastLogin, u.IsActive, u.FailedLoginAttempts, u.AccountLockedUntil,
                               CASE WHEN u.AccountLockedUntil > NOW() THEN TRUE ELSE FALSE END as IsLocked
                        FROM Users u 
                        WHERE u.Email = @email AND u.IsActive = 1";
                    
                    using (var command = new SqlCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@email", email);
                        
                        using (var reader = await command.ExecuteReaderAsync())
                        {
                            if (await reader.ReadAsync())
                            {
                                var user = new UserInfo
                                {
                                    UserId = reader.GetInt32("UserID"),
                                    Username = reader.GetString("Username"),
                                    Email = reader.GetString("Email"),
                                    PasswordHash = reader.GetString("PasswordHash"),
                                    Salt = reader.GetString("Salt"),
                                    CreatedAt = reader.GetDateTime("CreatedAt"),
                                    LastLogin = reader.IsDBNull("LastLogin") ? (DateTime?)null : reader.GetDateTime("LastLogin"),
                                    IsActive = reader.GetBoolean("IsActive"),
                                    FailedLoginAttempts = reader.GetInt32("FailedLoginAttempts"),
                                    AccountLockedUntil = reader.IsDBNull("AccountLockedUntil") ? (DateTime?)null : reader.GetDateTime("AccountLockedUntil"),
                                    IsLocked = reader.GetBoolean("IsLocked")
                                };

                                // Get user roles
                                user.Roles = await GetUserRolesAsync(user.UserId);
                                
                                return user;
                            }
                        }
                    }
                }
            }
            catch
            {
                return null;
            }

            return null;
        }

        /// <summary>
        /// Gets user roles
        /// </summary>
        /// <param name="userId">User ID</param>
        /// <returns>List of role names</returns>
        public async Task<List<string>> GetUserRolesAsync(int userId)
        {
            var roles = new List<string>();
            
            if (userId <= 0)
                return roles;

            try
            {
                using (var connection = new SqlConnection(_connectionString))
                {
                    await connection.OpenAsync();
                    
                    string query = @"
                        SELECT r.RoleName 
                        FROM UserRoles ur
                        INNER JOIN Roles r ON ur.RoleID = r.RoleID
                        WHERE ur.UserID = @userId AND r.IsActive = 1";
                    
                    using (var command = new SqlCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@userId", userId);
                        
                        using (var reader = await command.ExecuteReaderAsync())
                        {
                            while (await reader.ReadAsync())
                            {
                                roles.Add(reader.GetString("RoleName"));
                            }
                        }
                    }
                }
            }
            catch
            {
                // Return empty list on error
            }

            return roles;
        }

        /// <summary>
        /// Gets role permissions - SECURITY FIXED: Uses parameterized queries
        /// </summary>
        /// <param name="roleNames">Role names</param>
        /// <returns>List of permissions</returns>
        public async Task<List<Permission>> GetRolePermissionsAsync(string[] roleNames)
        {
            var permissions = new List<Permission>();
            
            if (roleNames == null || roleNames.Length == 0)
                return permissions;

            try
            {
                using (var connection = new SqlConnection(_connectionString))
                {
                    await connection.OpenAsync();
                    
                    // SECURITY FIX: Use parameterized query instead of string.Format
                    // Build parameter placeholders safely
                    var parameterPlaceholders = new List<string>();
                    for (int i = 0; i < roleNames.Length; i++)
                    {
                        parameterPlaceholders.Add($"@role{i}");
                    }
                    
                    string query = $@"
                        SELECT DISTINCT p.PermissionID, p.Action, p.Resource, p.Description
                        FROM RolePermissions rp
                        INNER JOIN Roles r ON rp.RoleID = r.RoleID
                        INNER JOIN Permissions p ON rp.PermissionID = p.PermissionID
                        WHERE r.RoleName IN ({string.Join(",", parameterPlaceholders)}) AND r.IsActive = 1";
                    
                    using (var command = new SqlCommand(query, connection))
                    {
                        // Add parameters safely
                        for (int i = 0; i < roleNames.Length; i++)
                        {
                            command.Parameters.AddWithValue($"@role{i}", roleNames[i]);
                        }
                        
                        using (var reader = await command.ExecuteReaderAsync())
                        {
                            while (await reader.ReadAsync())
                            {
                                permissions.Add(new Permission
                                {
                                    PermissionId = reader.GetInt32("PermissionID"),
                                    Action = reader.GetString("Action"),
                                    Resource = reader.IsDBNull("Resource") ? null : reader.GetString("Resource"),
                                    Description = reader.IsDBNull("Description") ? null : reader.GetString("Description")
                                });
                            }
                        }
                    }
                }
            }
            catch
            {
                // Return empty list on error
            }

            return permissions;
        }

        /// <summary>
        /// Assigns a role to a user
        /// </summary>
        /// <param name="userId">User ID</param>
        /// <param name="roleName">Role name</param>
        public async Task AssignRoleToUserAsync(int userId, string roleName)
        {
            if (userId <= 0 || string.IsNullOrWhiteSpace(roleName))
                throw new ArgumentException("Invalid parameters");

            try
            {
                using (var connection = new SqlConnection(_connectionString))
                {
                    await connection.OpenAsync();
                    
                    string query = @"
                        INSERT INTO UserRoles (UserID, RoleID)
                        SELECT @userId, r.RoleID
                        FROM Roles r
                        WHERE r.RoleName = @roleName AND r.IsActive = 1";
                    
                    using (var command = new SqlCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@userId", userId);
                        command.Parameters.AddWithValue("@roleName", roleName);
                        
                        await command.ExecuteNonQueryAsync();
                    }
                }
            }
            catch (SqlException ex)
            {
                if (ex.Number == 1062) // Duplicate entry
                {
                    throw new InvalidOperationException("User already has this role");
                }
                throw new InvalidOperationException("Failed to assign role");
            }
        }

        /// <summary>
        /// Removes a role from a user
        /// </summary>
        /// <param name="userId">User ID</param>
        /// <param name="roleName">Role name</param>
        public async Task RemoveRoleFromUserAsync(int userId, string roleName)
        {
            if (userId <= 0 || string.IsNullOrWhiteSpace(roleName))
                throw new ArgumentException("Invalid parameters");

            try
            {
                using (var connection = new SqlConnection(_connectionString))
                {
                    await connection.OpenAsync();
                    
                    string query = @"
                        DELETE ur FROM UserRoles ur
                        INNER JOIN Roles r ON ur.RoleID = r.RoleID
                        WHERE ur.UserID = @userId AND r.RoleName = @roleName";
                    
                    using (var command = new SqlCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@userId", userId);
                        command.Parameters.AddWithValue("@roleName", roleName);
                        
                        await command.ExecuteNonQueryAsync();
                    }
                }
            }
            catch
            {
                throw new InvalidOperationException("Failed to remove role");
            }
        }

        /// <summary>
        /// Checks if a role exists
        /// </summary>
        /// <param name="roleName">Role name</param>
        /// <returns>True if role exists</returns>
        public async Task<bool> RoleExistsAsync(string roleName)
        {
            if (string.IsNullOrWhiteSpace(roleName))
                return false;

            try
            {
                using (var connection = new SqlConnection(_connectionString))
                {
                    await connection.OpenAsync();
                    
                    string query = "SELECT COUNT(*) FROM Roles WHERE RoleName = @roleName AND IsActive = 1";
                    
                    using (var command = new SqlCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@roleName", roleName);
                        
                        int count = Convert.ToInt32(await command.ExecuteScalarAsync());
                        return count > 0;
                    }
                }
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Gets all roles
        /// </summary>
        /// <returns>List of roles</returns>
        public async Task<List<Role>> GetAllRolesAsync()
        {
            var roles = new List<Role>();

            try
            {
                using (var connection = new SqlConnection(_connectionString))
                {
                    await connection.OpenAsync();
                    
                    string query = "SELECT RoleID, RoleName, Description, IsActive, CreatedAt FROM Roles WHERE IsActive = 1 ORDER BY RoleName";
                    
                    using (var command = new SqlCommand(query, connection))
                    {
                        using (var reader = await command.ExecuteReaderAsync())
                        {
                            while (await reader.ReadAsync())
                            {
                                roles.Add(new Role
                                {
                                    RoleId = reader.GetInt32("RoleID"),
                                    RoleName = reader.GetString("RoleName"),
                                    Description = reader.IsDBNull("Description") ? null : reader.GetString("Description"),
                                    IsActive = reader.GetBoolean("IsActive"),
                                    CreatedAt = reader.GetDateTime("CreatedAt")
                                });
                            }
                        }
                    }
                }
            }
            catch
            {
                // Return empty list on error
            }

            return roles;
        }

        /// <summary>
        /// Increments failed login attempts
        /// </summary>
        /// <param name="userId">User ID</param>
        public async Task IncrementFailedLoginAttemptsAsync(int userId)
        {
            if (userId <= 0)
                return;

            try
            {
                using (var connection = new SqlConnection(_connectionString))
                {
                    await connection.OpenAsync();
                    
                    string query = @"
                        UPDATE Users 
                        SET FailedLoginAttempts = FailedLoginAttempts + 1,
                            AccountLockedUntil = CASE 
                                WHEN FailedLoginAttempts >= 4 THEN DATE_ADD(NOW(), INTERVAL 30 MINUTE)
                                ELSE AccountLockedUntil
                            END
                        WHERE UserID = @userId";
                    
                    using (var command = new SqlCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@userId", userId);
                        await command.ExecuteNonQueryAsync();
                    }
                }
            }
            catch
            {
                // Log error but don't throw
            }
        }

        /// <summary>
        /// Resets failed login attempts
        /// </summary>
        /// <param name="userId">User ID</param>
        public async Task ResetFailedLoginAttemptsAsync(int userId)
        {
            if (userId <= 0)
                return;

            try
            {
                using (var connection = new SqlConnection(_connectionString))
                {
                    await connection.OpenAsync();
                    
                    string query = @"
                        UPDATE Users 
                        SET FailedLoginAttempts = 0, 
                            AccountLockedUntil = NULL
                        WHERE UserID = @userId";
                    
                    using (var command = new SqlCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@userId", userId);
                        await command.ExecuteNonQueryAsync();
                    }
                }
            }
            catch
            {
                // Log error but don't throw
            }
        }

        /// <summary>
        /// Updates last login time
        /// </summary>
        /// <param name="userId">User ID</param>
        public async Task UpdateLastLoginAsync(int userId)
        {
            if (userId <= 0)
                return;

            try
            {
                using (var connection = new SqlConnection(_connectionString))
                {
                    await connection.OpenAsync();
                    
                    string query = "UPDATE Users SET LastLogin = NOW() WHERE UserID = @userId";
                    
                    using (var command = new SqlCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@userId", userId);
                        await command.ExecuteNonQueryAsync();
                    }
                }
            }
            catch
            {
                // Log error but don't throw
            }
        }

        /// <summary>
        /// Updates user password
        /// </summary>
        /// <param name="userId">User ID</param>
        /// <param name="passwordHash">New password hash</param>
        /// <param name="salt">New salt</param>
        public async Task UpdateUserPasswordAsync(int userId, string passwordHash, string salt)
        {
            if (userId <= 0 || string.IsNullOrWhiteSpace(passwordHash) || string.IsNullOrWhiteSpace(salt))
                throw new ArgumentException("Invalid parameters");

            try
            {
                using (var connection = new SqlConnection(_connectionString))
                {
                    await connection.OpenAsync();
                    
                    string query = "UPDATE Users SET PasswordHash = @passwordHash, Salt = @salt WHERE UserID = @userId";
                    
                    using (var command = new SqlCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@userId", userId);
                        command.Parameters.AddWithValue("@passwordHash", passwordHash);
                        command.Parameters.AddWithValue("@salt", salt);
                        
                        await command.ExecuteNonQueryAsync();
                    }
                }
            }
            catch
            {
                throw new InvalidOperationException("Failed to update password");
            }
        }

        /// <summary>
        /// Creates a session
        /// </summary>
        /// <param name="sessionId">Session ID</param>
        /// <param name="userId">User ID</param>
        /// <param name="expiresAt">Expiration time</param>
        /// <param name="ipAddress">IP address</param>
        /// <param name="userAgent">User agent</param>
        public async Task CreateSessionAsync(string sessionId, int userId, DateTime expiresAt, string ipAddress, string userAgent)
        {
            if (string.IsNullOrWhiteSpace(sessionId) || userId <= 0)
                throw new ArgumentException("Invalid parameters");

            try
            {
                using (var connection = new SqlConnection(_connectionString))
                {
                    await connection.OpenAsync();
                    
                    string query = @"
                        INSERT INTO UserSessions (SessionID, UserID, ExpiresAt, IPAddress, UserAgent)
                        VALUES (@sessionId, @userId, @expiresAt, @ipAddress, @userAgent)";
                    
                    using (var command = new SqlCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@sessionId", sessionId);
                        command.Parameters.AddWithValue("@userId", userId);
                        command.Parameters.AddWithValue("@expiresAt", expiresAt);
                        command.Parameters.AddWithValue("@ipAddress", ipAddress ?? string.Empty);
                        command.Parameters.AddWithValue("@userAgent", userAgent ?? string.Empty);
                        
                        await command.ExecuteNonQueryAsync();
                    }
                }
            }
            catch
            {
                throw new InvalidOperationException("Failed to create session");
            }
        }

        /// <summary>
        /// Gets session information
        /// </summary>
        /// <param name="sessionId">Session ID</param>
        /// <returns>Session information or null if not found</returns>
        public async Task<SessionInfo> GetSessionAsync(string sessionId)
        {
            if (string.IsNullOrWhiteSpace(sessionId))
                return null;

            try
            {
                using (var connection = new SqlConnection(_connectionString))
                {
                    await connection.OpenAsync();
                    
                    string query = @"
                        SELECT SessionID, UserID, CreatedAt, ExpiresAt, IPAddress, UserAgent, IsActive
                        FROM UserSessions 
                        WHERE SessionID = @sessionId AND IsActive = 1 AND ExpiresAt > NOW()";
                    
                    using (var command = new SqlCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@sessionId", sessionId);
                        
                        using (var reader = await command.ExecuteReaderAsync())
                        {
                            if (await reader.ReadAsync())
                            {
                                return new SessionInfo
                                {
                                    SessionId = reader.GetString("SessionID"),
                                    UserId = reader.GetInt32("UserID"),
                                    CreatedAt = reader.GetDateTime("CreatedAt"),
                                    ExpiresAt = reader.GetDateTime("ExpiresAt"),
                                    IpAddress = reader.IsDBNull("IPAddress") ? null : reader.GetString("IPAddress"),
                                    UserAgent = reader.IsDBNull("UserAgent") ? null : reader.GetString("UserAgent"),
                                    IsActive = reader.GetBoolean("IsActive")
                                };
                            }
                        }
                    }
                }
            }
            catch
            {
                return null;
            }

            return null;
        }

        /// <summary>
        /// Invalidates a session
        /// </summary>
        /// <param name="sessionId">Session ID</param>
        public async Task InvalidateSessionAsync(string sessionId)
        {
            if (string.IsNullOrWhiteSpace(sessionId))
                return;

            try
            {
                using (var connection = new SqlConnection(_connectionString))
                {
                    await connection.OpenAsync();
                    
                    string query = "UPDATE UserSessions SET IsActive = 0 WHERE SessionID = @sessionId";
                    
                    using (var command = new SqlCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@sessionId", sessionId);
                        await command.ExecuteNonQueryAsync();
                    }
                }
            }
            catch
            {
                // Log error but don't throw
            }
        }

        /// <summary>
        /// Invalidates all sessions for a user
        /// </summary>
        /// <param name="userId">User ID</param>
        public async Task InvalidateAllUserSessionsAsync(int userId)
        {
            if (userId <= 0)
                return;

            try
            {
                using (var connection = new SqlConnection(_connectionString))
                {
                    await connection.OpenAsync();
                    
                    string query = "UPDATE UserSessions SET IsActive = 0 WHERE UserID = @userId";
                    
                    using (var command = new SqlCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@userId", userId);
                        await command.ExecuteNonQueryAsync();
                    }
                }
            }
            catch
            {
                // Log error but don't throw
            }
        }

        /// <summary>
        /// Updates session expiration
        /// </summary>
        /// <param name="sessionId">Session ID</param>
        /// <param name="expiresAt">New expiration time</param>
        public async Task UpdateSessionExpirationAsync(string sessionId, DateTime expiresAt)
        {
            if (string.IsNullOrWhiteSpace(sessionId))
                return;

            try
            {
                using (var connection = new SqlConnection(_connectionString))
                {
                    await connection.OpenAsync();
                    
                    string query = "UPDATE UserSessions SET ExpiresAt = @expiresAt WHERE SessionID = @sessionId";
                    
                    using (var command = new SqlCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@sessionId", sessionId);
                        command.Parameters.AddWithValue("@expiresAt", expiresAt);
                        await command.ExecuteNonQueryAsync();
                    }
                }
            }
            catch
            {
                // Log error but don't throw
            }
        }

        /// <summary>
        /// Cleans up expired sessions
        /// </summary>
        public async Task CleanupExpiredSessionsAsync()
        {
            try
            {
                using (var connection = new SqlConnection(_connectionString))
                {
                    await connection.OpenAsync();
                    
                    string query = "DELETE FROM UserSessions WHERE ExpiresAt <= NOW()";
                    
                    using (var command = new SqlCommand(query, connection))
                    {
                        await command.ExecuteNonQueryAsync();
                    }
                }
            }
            catch
            {
                // Log error but don't throw
            }
        }

        /// <summary>
        /// Tests database connection
        /// </summary>
        /// <returns>True if connection is successful</returns>
        public async Task<bool> TestConnectionAsync()
        {
            try
            {
                using (var connection = new SqlConnection(_connectionString))
                {
                    await connection.OpenAsync();
                    return true;
                }
            }
            catch
            {
                return false;
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    _connection?.Dispose();
                }
                _disposed = true;
            }
        }
    }

    /// <summary>
    /// Result of user authentication
    /// </summary>
    public class AuthenticationResult
    {
        public bool IsSuccess { get; set; }
        public int UserId { get; set; }
        public string ErrorMessage { get; set; }
    }

    /// <summary>
    /// User information model
    /// </summary>
    public class UserInfo
    {
        public int UserId { get; set; }
        public string Username { get; set; }
        public string Email { get; set; }
        public string PasswordHash { get; set; }
        public string Salt { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? LastLogin { get; set; }
        public bool IsActive { get; set; }
        public bool IsLocked { get; set; }
        public int FailedLoginAttempts { get; set; }
        public DateTime? AccountLockedUntil { get; set; }
        public List<string> Roles { get; set; } = new List<string>();
    }
}
