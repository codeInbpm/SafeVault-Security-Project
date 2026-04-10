using System;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Http.Results;
using SafeVault.Security;
using SafeVault.Data;
using System.Net;
using System.Net.Http;
using System.Web;

namespace SafeVault.Controllers
{
    /// <summary>
    /// Secure API controller for user management operations
    /// </summary>
    [RoutePrefix("api/users")]
    public class UserController : ApiController
    {
        private readonly SecureDatabaseManager _dbManager;
        private readonly string _connectionString;

        public UserController()
        {
            // In production, use dependency injection and configuration
            _connectionString = "Server=localhost;Database=SafeVault;Integrated Security=true;TrustServerCertificate=true;";
            _dbManager = new SecureDatabaseManager(_connectionString);
        }

        /// <summary>
        /// Creates a new user with secure validation
        /// </summary>
        /// <param name="request">User creation request</param>
        /// <returns>Creation result</returns>
        [HttpPost]
        [Route("")]
        public async Task<IHttpActionResult> CreateUser([FromBody] CreateUserRequest request)
        {
            try
            {
                // Get client information for audit logging
                var clientInfo = GetClientInfo();

                // Validate input
                if (request == null)
                {
                    await _dbManager.LogAuditEventAsync(null, "USER_CREATION_FAILED", "Null request received", clientInfo.IpAddress, clientInfo.UserAgent);
                    return BadRequest("Request cannot be null");
                }

                // Validate username
                var usernameValidation = SecureInputValidator.ValidateUsername(request.Username);
                if (!usernameValidation.IsValid)
                {
                    await _dbManager.LogAuditEventAsync(null, "USER_CREATION_FAILED", $"Invalid username: {usernameValidation.ErrorMessage}", clientInfo.IpAddress, clientInfo.UserAgent);
                    return BadRequest($"Username validation failed: {usernameValidation.ErrorMessage}");
                }

                // Validate email
                var emailValidation = SecureInputValidator.ValidateEmail(request.Email);
                if (!emailValidation.IsValid)
                {
                    await _dbManager.LogAuditEventAsync(null, "USER_CREATION_FAILED", $"Invalid email: {emailValidation.ErrorMessage}", clientInfo.IpAddress, clientInfo.UserAgent);
                    return BadRequest($"Email validation failed: {emailValidation.ErrorMessage}");
                }

                // Validate password if provided
                if (!string.IsNullOrEmpty(request.Password))
                {
                    var passwordValidation = SecureInputValidator.ValidatePassword(request.Password);
                    if (!passwordValidation.IsValid)
                    {
                        await _dbManager.LogAuditEventAsync(null, "USER_CREATION_FAILED", $"Invalid password: {passwordValidation.ErrorMessage}", clientInfo.IpAddress, clientInfo.UserAgent);
                        return BadRequest($"Password validation failed: {passwordValidation.ErrorMessage}");
                    }
                }

                // Generate salt and hash password
                string salt = SecureInputValidator.GenerateSalt();
                string passwordHash = SecureInputValidator.HashPassword(request.Password ?? "defaultPassword123!", salt);

                // Create user in database
                int userId = await _dbManager.CreateUserAsync(
                    usernameValidation.SanitizedValue,
                    emailValidation.SanitizedValue,
                    passwordHash,
                    salt,
                    clientInfo.IpAddress,
                    clientInfo.UserAgent
                );

                if (userId > 0)
                {
                    var response = new CreateUserResponse
                    {
                        Success = true,
                        UserId = userId,
                        Message = "User created successfully"
                    };

                    return Ok(response);
                }
                else
                {
                    await _dbManager.LogAuditEventAsync(null, "USER_CREATION_FAILED", "Database operation failed", clientInfo.IpAddress, clientInfo.UserAgent);
                    return InternalServerError(new Exception("Failed to create user"));
                }
            }
            catch (InvalidOperationException ex)
            {
                var clientInfo = GetClientInfo();
                await _dbManager.LogAuditEventAsync(null, "USER_CREATION_FAILED", ex.Message, clientInfo.IpAddress, clientInfo.UserAgent);
                return BadRequest(ex.Message);
            }
            catch (Exception ex)
            {
                var clientInfo = GetClientInfo();
                await _dbManager.LogAuditEventAsync(null, "USER_CREATION_ERROR", ex.Message, clientInfo.IpAddress, clientInfo.UserAgent);
                return InternalServerError(ex);
            }
        }

        /// <summary>
        /// Authenticates a user with secure validation
        /// </summary>
        /// <param name="request">Authentication request</param>
        /// <returns>Authentication result</returns>
        [HttpPost]
        [Route("authenticate")]
        public async Task<IHttpActionResult> AuthenticateUser([FromBody] AuthenticateUserRequest request)
        {
            try
            {
                var clientInfo = GetClientInfo();

                // Validate input
                if (request == null)
                {
                    await _dbManager.LogAuditEventAsync(null, "AUTHENTICATION_FAILED", "Null request received", clientInfo.IpAddress, clientInfo.UserAgent);
                    return BadRequest("Request cannot be null");
                }

                // Validate username
                var usernameValidation = SecureInputValidator.ValidateUsername(request.Username);
                if (!usernameValidation.IsValid)
                {
                    await _dbManager.LogAuditEventAsync(null, "AUTHENTICATION_FAILED", $"Invalid username format", clientInfo.IpAddress, clientInfo.UserAgent);
                    return BadRequest("Invalid username format");
                }

                if (string.IsNullOrEmpty(request.Password))
                {
                    await _dbManager.LogAuditEventAsync(null, "AUTHENTICATION_FAILED", "Empty password", clientInfo.IpAddress, clientInfo.UserAgent);
                    return BadRequest("Password is required");
                }

                // Hash the provided password (in real implementation, you'd need to retrieve the salt from database)
                // For this example, we'll use a simple hash
                string passwordHash = SecureInputValidator.HashPassword(request.Password, "defaultSalt");

                // Authenticate user
                var authResult = await _dbManager.AuthenticateUserAsync(
                    usernameValidation.SanitizedValue,
                    passwordHash,
                    clientInfo.IpAddress,
                    clientInfo.UserAgent
                );

                if (authResult.IsSuccess)
                {
                    var response = new AuthenticateUserResponse
                    {
                        Success = true,
                        UserId = authResult.UserId,
                        Message = "Authentication successful"
                    };

                    return Ok(response);
                }
                else
                {
                    return Unauthorized();
                }
            }
            catch (Exception ex)
            {
                var clientInfo = GetClientInfo();
                await _dbManager.LogAuditEventAsync(null, "AUTHENTICATION_ERROR", ex.Message, clientInfo.IpAddress, clientInfo.UserAgent);
                return InternalServerError(ex);
            }
        }

        /// <summary>
        /// Retrieves user information by ID
        /// </summary>
        /// <param name="id">User ID</param>
        /// <returns>User information</returns>
        [HttpGet]
        [Route("{id}")]
        public async Task<IHttpActionResult> GetUser(int id)
        {
            try
            {
                var clientInfo = GetClientInfo();

                if (id <= 0)
                {
                    await _dbManager.LogAuditEventAsync(null, "USER_RETRIEVAL_FAILED", "Invalid user ID", clientInfo.IpAddress, clientInfo.UserAgent);
                    return BadRequest("Invalid user ID");
                }

                var user = await _dbManager.GetUserByIdAsync(id);
                
                if (user == null)
                {
                    await _dbManager.LogAuditEventAsync(null, "USER_RETRIEVAL_FAILED", $"User not found: {id}", clientInfo.IpAddress, clientInfo.UserAgent);
                    return NotFound();
                }

                await _dbManager.LogAuditEventAsync(id, "USER_RETRIEVED", "User information retrieved", clientInfo.IpAddress, clientInfo.UserAgent);

                // Return sanitized user information (exclude sensitive data)
                var response = new GetUserResponse
                {
                    Success = true,
                    User = new UserDto
                    {
                        UserId = user.UserId,
                        Username = user.Username,
                        Email = user.Email,
                        CreatedAt = user.CreatedAt,
                        LastLogin = user.LastLogin,
                        IsActive = user.IsActive
                    }
                };

                return Ok(response);
            }
            catch (Exception ex)
            {
                var clientInfo = GetClientInfo();
                await _dbManager.LogAuditEventAsync(null, "USER_RETRIEVAL_ERROR", ex.Message, clientInfo.IpAddress, clientInfo.UserAgent);
                return InternalServerError(ex);
            }
        }

        /// <summary>
        /// Searches users with secure input validation
        /// </summary>
        /// <param name="searchTerm">Search term</param>
        /// <param name="limit">Maximum results</param>
        /// <returns>Search results</returns>
        [HttpGet]
        [Route("search")]
        public async Task<IHttpActionResult> SearchUsers([FromUri] string searchTerm, [FromUri] int limit = 50)
        {
            try
            {
                var clientInfo = GetClientInfo();

                // Validate limit
                if (limit <= 0 || limit > 100)
                {
                    limit = 50;
                }

                var users = await _dbManager.SearchUsersAsync(searchTerm, limit);

                await _dbManager.LogAuditEventAsync(null, "USER_SEARCH", $"Search performed: {searchTerm}", clientInfo.IpAddress, clientInfo.UserAgent);

                var response = new SearchUsersResponse
                {
                    Success = true,
                    Users = users.ConvertAll(u => new UserDto
                    {
                        UserId = u.UserId,
                        Username = u.Username,
                        Email = u.Email,
                        CreatedAt = u.CreatedAt,
                        LastLogin = u.LastLogin,
                        IsActive = u.IsActive
                    }),
                    Count = users.Count
                };

                return Ok(response);
            }
            catch (ArgumentException ex)
            {
                var clientInfo = GetClientInfo();
                await _dbManager.LogAuditEventAsync(null, "USER_SEARCH_FAILED", ex.Message, clientInfo.IpAddress, clientInfo.UserAgent);
                return BadRequest(ex.Message);
            }
            catch (Exception ex)
            {
                var clientInfo = GetClientInfo();
                await _dbManager.LogAuditEventAsync(null, "USER_SEARCH_ERROR", ex.Message, clientInfo.IpAddress, clientInfo.UserAgent);
                return InternalServerError(ex);
            }
        }

        /// <summary>
        /// Tests the API health and database connection
        /// </summary>
        /// <returns>Health status</returns>
        [HttpGet]
        [Route("health")]
        public async Task<IHttpActionResult> HealthCheck()
        {
            try
            {
                bool dbConnected = await _dbManager.TestConnectionAsync();
                
                var response = new HealthCheckResponse
                {
                    Success = true,
                    DatabaseConnected = dbConnected,
                    Timestamp = DateTime.UtcNow,
                    Message = dbConnected ? "All systems operational" : "Database connection failed"
                };

                return Ok(response);
            }
            catch (Exception ex)
            {
                return InternalServerError(ex);
            }
        }

        /// <summary>
        /// Gets client information for audit logging
        /// </summary>
        /// <returns>Client information</returns>
        private ClientInfo GetClientInfo()
        {
            var request = HttpContext.Current?.Request;
            
            return new ClientInfo
            {
                IpAddress = request?.UserHostAddress ?? "Unknown",
                UserAgent = request?.UserAgent ?? "Unknown"
            };
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _dbManager?.Dispose();
            }
            base.Dispose(disposing);
        }
    }

    // Request/Response models
    public class CreateUserRequest
    {
        public string Username { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
    }

    public class CreateUserResponse
    {
        public bool Success { get; set; }
        public int UserId { get; set; }
        public string Message { get; set; }
    }

    public class AuthenticateUserRequest
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }

    public class AuthenticateUserResponse
    {
        public bool Success { get; set; }
        public int UserId { get; set; }
        public string Message { get; set; }
    }

    public class GetUserResponse
    {
        public bool Success { get; set; }
        public UserDto User { get; set; }
    }

    public class SearchUsersResponse
    {
        public bool Success { get; set; }
        public System.Collections.Generic.List<UserDto> Users { get; set; }
        public int Count { get; set; }
    }

    public class HealthCheckResponse
    {
        public bool Success { get; set; }
        public bool DatabaseConnected { get; set; }
        public DateTime Timestamp { get; set; }
        public string Message { get; set; }
    }

    public class UserDto
    {
        public int UserId { get; set; }
        public string Username { get; set; }
        public string Email { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? LastLogin { get; set; }
        public bool IsActive { get; set; }
    }

    public class ClientInfo
    {
        public string IpAddress { get; set; }
        public string UserAgent { get; set; }
    }
}
