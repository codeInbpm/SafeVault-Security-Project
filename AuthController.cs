using System;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Http.Results;
using SafeVault.Services;
using SafeVault.Data;
using System.Net;
using System.Net.Http;
using System.Web;

namespace SafeVault.Controllers
{
    /// <summary>
    /// Authentication and authorization API controller
    /// </summary>
    [RoutePrefix("api/auth")]
    public class AuthController : ApiController
    {
        private readonly AuthenticationService _authService;
        private readonly AuthorizationService _authzService;
        private readonly SessionManager _sessionManager;
        private readonly SecureDatabaseManager _dbManager;

        public AuthController()
        {
            var connectionString = "Server=localhost;Database=SafeVault;Integrated Security=true;TrustServerCertificate=true;";
            _dbManager = new SecureDatabaseManager(connectionString);
            _sessionManager = new SessionManager(_dbManager);
            var auditLogger = new AuditLogger(_dbManager);
            _authService = new AuthenticationService(_dbManager, _sessionManager, auditLogger);
            _authzService = new AuthorizationService(_dbManager, _sessionManager, auditLogger);
        }

        /// <summary>
        /// Authenticates a user and returns a session token
        /// </summary>
        /// <param name="request">Login request</param>
        /// <returns>Authentication result</returns>
        [HttpPost]
        [Route("login")]
        public async Task<IHttpActionResult> Login([FromBody] LoginRequest request)
        {
            try
            {
                var clientInfo = GetClientInfo();

                if (request == null)
                {
                    return BadRequest("Request cannot be null");
                }

                var result = await _authService.AuthenticateUserAsync(
                    request.Username,
                    request.Password,
                    clientInfo.IpAddress,
                    clientInfo.UserAgent
                );

                if (result.IsSuccess)
                {
                    var response = new LoginResponse
                    {
                        Success = true,
                        Token = result.Token,
                        SessionId = result.SessionId,
                        ExpiresAt = result.ExpiresAt,
                        User = new UserInfo
                        {
                            UserId = result.UserId,
                            Username = result.Username,
                            Email = result.Email,
                            Roles = result.Roles
                        }
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
                return InternalServerError(ex);
            }
        }

        /// <summary>
        /// Registers a new user
        /// </summary>
        /// <param name="request">Registration request</param>
        /// <returns>Registration result</returns>
        [HttpPost]
        [Route("register")]
        public async Task<IHttpActionResult> Register([FromBody] RegisterRequest request)
        {
            try
            {
                var clientInfo = GetClientInfo();

                if (request == null)
                {
                    return BadRequest("Request cannot be null");
                }

                var result = await _authService.RegisterUserAsync(
                    request.Username,
                    request.Email,
                    request.Password,
                    clientInfo.IpAddress,
                    clientInfo.UserAgent
                );

                if (result.IsSuccess)
                {
                    var response = new RegisterResponse
                    {
                        Success = true,
                        UserId = result.UserId,
                        Message = result.Message
                    };

                    return Ok(response);
                }
                else
                {
                    return BadRequest(result.ErrorMessage);
                }
            }
            catch (Exception ex)
            {
                return InternalServerError(ex);
            }
        }

        /// <summary>
        /// Logs out a user and invalidates their session
        /// </summary>
        /// <param name="request">Logout request</param>
        /// <returns>Logout result</returns>
        [HttpPost]
        [Route("logout")]
        public async Task<IHttpActionResult> Logout([FromBody] LogoutRequest request)
        {
            try
            {
                var clientInfo = GetClientInfo();

                var result = await _authService.LogoutUserAsync(
                    request.SessionId,
                    clientInfo.IpAddress,
                    clientInfo.UserAgent
                );

                if (result.IsSuccess)
                {
                    return Ok(new { Success = true, Message = result.Message });
                }
                else
                {
                    return BadRequest(result.ErrorMessage);
                }
            }
            catch (Exception ex)
            {
                return InternalServerError(ex);
            }
        }

        /// <summary>
        /// Changes a user's password
        /// </summary>
        /// <param name="request">Password change request</param>
        /// <returns>Password change result</returns>
        [HttpPost]
        [Route("change-password")]
        public async Task<IHttpActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
        {
            try
            {
                var clientInfo = GetClientInfo();

                if (request == null)
                {
                    return BadRequest("Request cannot be null");
                }

                // Validate session
                var session = await _sessionManager.ValidateTokenAsync(request.Token);
                if (session == null)
                {
                    return Unauthorized();
                }

                var result = await _authService.ChangePasswordAsync(
                    session.UserId,
                    request.CurrentPassword,
                    request.NewPassword,
                    clientInfo.IpAddress,
                    clientInfo.UserAgent
                );

                if (result.IsSuccess)
                {
                    return Ok(new { Success = true, Message = result.Message });
                }
                else
                {
                    return BadRequest(result.ErrorMessage);
                }
            }
            catch (Exception ex)
            {
                return InternalServerError(ex);
            }
        }

        /// <summary>
        /// Validates a session token and returns user information
        /// </summary>
        /// <param name="request">Token validation request</param>
        /// <returns>Validation result</returns>
        [HttpPost]
        [Route("validate")]
        public async Task<IHttpActionResult> ValidateToken([FromBody] ValidateTokenRequest request)
        {
            try
            {
                var clientInfo = GetClientInfo();

                if (request == null || string.IsNullOrWhiteSpace(request.Token))
                {
                    return BadRequest("Token is required");
                }

                var result = await _authzService.AuthorizeSessionAsync(
                    request.Token,
                    "ReadUser", // Basic read permission
                    null,
                    clientInfo.IpAddress,
                    clientInfo.UserAgent
                );

                if (result.IsAuthorized)
                {
                    var response = new ValidateTokenResponse
                    {
                        IsAuthorized = true,
                        UserId = result.UserId,
                        Username = result.Username,
                        Email = result.Email,
                        Roles = result.Roles,
                        SessionId = result.SessionId
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
                return InternalServerError(ex);
            }
        }

        /// <summary>
        /// Refreshes a session token
        /// </summary>
        /// <param name="request">Token refresh request</param>
        /// <returns>Refresh result</returns>
        [HttpPost]
        [Route("refresh")]
        public async Task<IHttpActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
        {
            try
            {
                if (request == null || string.IsNullOrWhiteSpace(request.Token))
                {
                    return BadRequest("Token is required");
                }

                var session = await _sessionManager.ValidateTokenAsync(request.Token);
                if (session == null)
                {
                    return Unauthorized();
                }

                var newSession = await _sessionManager.RefreshSessionAsync(session.SessionId);
                if (newSession == null)
                {
                    return Unauthorized();
                }

                var response = new RefreshTokenResponse
                {
                    Success = true,
                    Token = newSession.Token,
                    SessionId = newSession.SessionId,
                    ExpiresAt = newSession.ExpiresAt
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
    public class LoginRequest
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }

    public class LoginResponse
    {
        public bool Success { get; set; }
        public string Token { get; set; }
        public string SessionId { get; set; }
        public DateTime ExpiresAt { get; set; }
        public UserInfo User { get; set; }
    }

    public class RegisterRequest
    {
        public string Username { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
    }

    public class RegisterResponse
    {
        public bool Success { get; set; }
        public int UserId { get; set; }
        public string Message { get; set; }
    }

    public class LogoutRequest
    {
        public string SessionId { get; set; }
    }

    public class ChangePasswordRequest
    {
        public string Token { get; set; }
        public string CurrentPassword { get; set; }
        public string NewPassword { get; set; }
    }

    public class ValidateTokenRequest
    {
        public string Token { get; set; }
    }

    public class ValidateTokenResponse
    {
        public bool IsAuthorized { get; set; }
        public int UserId { get; set; }
        public string Username { get; set; }
        public string Email { get; set; }
        public System.Collections.Generic.List<string> Roles { get; set; }
        public string SessionId { get; set; }
    }

    public class RefreshTokenRequest
    {
        public string Token { get; set; }
    }

    public class RefreshTokenResponse
    {
        public bool Success { get; set; }
        public string Token { get; set; }
        public string SessionId { get; set; }
        public DateTime ExpiresAt { get; set; }
    }

    public class UserInfo
    {
        public int UserId { get; set; }
        public string Username { get; set; }
        public string Email { get; set; }
        public System.Collections.Generic.List<string> Roles { get; set; }
    }
}
