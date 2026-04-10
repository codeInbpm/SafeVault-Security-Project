using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using SafeVault.Data;
using System.Data;
using System.Data.SqlClient;

namespace SafeVault.Services
{
    /// <summary>
    /// Secure session management service with JWT-like tokens
    /// </summary>
    public class SessionManager
    {
        private readonly SecureDatabaseManager _dbManager;
        private readonly string _secretKey;
        private readonly TimeSpan _sessionTimeout;

        public SessionManager(SecureDatabaseManager dbManager, string secretKey = null, TimeSpan? sessionTimeout = null)
        {
            _dbManager = dbManager ?? throw new ArgumentNullException(nameof(dbManager));
            _secretKey = secretKey ?? GenerateSecretKey();
            _sessionTimeout = sessionTimeout ?? TimeSpan.FromHours(8);
        }

        /// <summary>
        /// Creates a new session for a user
        /// </summary>
        /// <param name="userId">User ID</param>
        /// <param name="ipAddress">Client IP address</param>
        /// <param name="userAgent">Client user agent</param>
        /// <returns>Session information</returns>
        public async Task<SessionInfo> CreateSessionAsync(int userId, string ipAddress, string userAgent)
        {
            try
            {
                // Generate session ID
                string sessionId = GenerateSessionId();
                
                // Generate JWT-like token
                string token = GenerateToken(userId, sessionId);
                
                // Calculate expiration
                DateTime expiresAt = DateTime.UtcNow.Add(_sessionTimeout);
                
                // Store session in database
                await _dbManager.CreateSessionAsync(sessionId, userId, expiresAt, ipAddress, userAgent);
                
                return new SessionInfo
                {
                    SessionId = sessionId,
                    UserId = userId,
                    Token = token,
                    CreatedAt = DateTime.UtcNow,
                    ExpiresAt = expiresAt,
                    IsActive = true
                };
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Failed to create session", ex);
            }
        }

        /// <summary>
        /// Validates a session and returns session information
        /// </summary>
        /// <param name="sessionId">Session ID</param>
        /// <returns>Session information or null if invalid</returns>
        public async Task<SessionInfo> GetSessionAsync(string sessionId)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(sessionId))
                    return null;

                return await _dbManager.GetSessionAsync(sessionId);
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Validates a token and returns session information
        /// </summary>
        /// <param name="token">JWT-like token</param>
        /// <returns>Session information or null if invalid</returns>
        public async Task<SessionInfo> ValidateTokenAsync(string token)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(token))
                    return null;

                // Parse token to extract session ID
                string sessionId = ExtractSessionIdFromToken(token);
                if (string.IsNullOrWhiteSpace(sessionId))
                    return null;

                // Get session from database
                var session = await _dbManager.GetSessionAsync(sessionId);
                if (session == null || !session.IsActive || session.ExpiresAt <= DateTime.UtcNow)
                    return null;

                // Verify token signature
                if (!VerifyTokenSignature(token, session.UserId, sessionId))
                    return null;

                return session;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Invalidates a session
        /// </summary>
        /// <param name="sessionId">Session ID</param>
        public async Task InvalidateSessionAsync(string sessionId)
        {
            try
            {
                if (!string.IsNullOrWhiteSpace(sessionId))
                {
                    await _dbManager.InvalidateSessionAsync(sessionId);
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
            try
            {
                await _dbManager.InvalidateAllUserSessionsAsync(userId);
            }
            catch
            {
                // Log error but don't throw
            }
        }

        /// <summary>
        /// Refreshes a session (extends expiration)
        /// </summary>
        /// <param name="sessionId">Session ID</param>
        /// <returns>New session information</returns>
        public async Task<SessionInfo> RefreshSessionAsync(string sessionId)
        {
            try
            {
                var session = await _dbManager.GetSessionAsync(sessionId);
                if (session == null || !session.IsActive)
                    return null;

                // Extend expiration
                DateTime newExpiresAt = DateTime.UtcNow.Add(_sessionTimeout);
                await _dbManager.UpdateSessionExpirationAsync(sessionId, newExpiresAt);

                // Generate new token
                string newToken = GenerateToken(session.UserId, sessionId);

                return new SessionInfo
                {
                    SessionId = sessionId,
                    UserId = session.UserId,
                    Token = newToken,
                    CreatedAt = session.CreatedAt,
                    ExpiresAt = newExpiresAt,
                    IsActive = true
                };
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Cleans up expired sessions
        /// </summary>
        public async Task CleanupExpiredSessionsAsync()
        {
            try
            {
                await _dbManager.CleanupExpiredSessionsAsync();
            }
            catch
            {
                // Log error but don't throw
            }
        }

        /// <summary>
        /// Generates a secure session ID
        /// </summary>
        /// <returns>Session ID</returns>
        private string GenerateSessionId()
        {
            using (var rng = new RNGCryptoServiceProvider())
            {
                byte[] bytes = new byte[32];
                rng.GetBytes(bytes);
                return Convert.ToBase64String(bytes).Replace("+", "-").Replace("/", "_").Replace("=", "");
            }
        }

        /// <summary>
        /// Generates a JWT-like token
        /// </summary>
        /// <param name="userId">User ID</param>
        /// <param name="sessionId">Session ID</param>
        /// <returns>JWT-like token</returns>
        private string GenerateToken(int userId, string sessionId)
        {
            try
            {
                // Create header
                var header = new
                {
                    alg = "HS256",
                    typ = "JWT"
                };

                // Create payload
                var payload = new
                {
                    sub = userId.ToString(),
                    sid = sessionId,
                    iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                    exp = DateTimeOffset.UtcNow.Add(_sessionTimeout).ToUnixTimeSeconds()
                };

                // Encode header and payload
                string headerJson = System.Text.Json.JsonSerializer.Serialize(header);
                string payloadJson = System.Text.Json.JsonSerializer.Serialize(payload);
                
                string headerEncoded = Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
                string payloadEncoded = Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));

                // Create signature
                string dataToSign = $"{headerEncoded}.{payloadEncoded}";
                string signature = CreateSignature(dataToSign);

                return $"{headerEncoded}.{payloadEncoded}.{signature}";
            }
            catch
            {
                throw new InvalidOperationException("Failed to generate token");
            }
        }

        /// <summary>
        /// Creates a signature for the token
        /// </summary>
        /// <param name="data">Data to sign</param>
        /// <returns>Signature</returns>
        private string CreateSignature(string data)
        {
            using (var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(_secretKey)))
            {
                byte[] signatureBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
                return Base64UrlEncode(signatureBytes);
            }
        }

        /// <summary>
        /// Verifies a token signature
        /// </summary>
        /// <param name="token">Token to verify</param>
        /// <param name="userId">Expected user ID</param>
        /// <param name="sessionId">Expected session ID</param>
        /// <returns>True if signature is valid</returns>
        private bool VerifyTokenSignature(string token, int userId, string sessionId)
        {
            try
            {
                string[] parts = token.Split('.');
                if (parts.Length != 3)
                    return false;

                string headerEncoded = parts[0];
                string payloadEncoded = parts[1];
                string signature = parts[2];

                // Verify signature
                string dataToVerify = $"{headerEncoded}.{payloadEncoded}";
                string expectedSignature = CreateSignature(dataToVerify);

                if (!SecureCompare(signature, expectedSignature))
                    return false;

                // Verify payload
                byte[] payloadBytes = Base64UrlDecode(payloadEncoded);
                string payloadJson = Encoding.UTF8.GetString(payloadBytes);
                
                var payload = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(payloadJson);
                
                if (!payload.ContainsKey("sub") || !payload.ContainsKey("sid"))
                    return false;

                if (payload["sub"].ToString() != userId.ToString() || payload["sid"].ToString() != sessionId)
                    return false;

                // Check expiration
                if (payload.ContainsKey("exp"))
                {
                    long exp = Convert.ToInt64(payload["exp"]);
                    if (DateTimeOffset.FromUnixTimeSeconds(exp) <= DateTimeOffset.UtcNow)
                        return false;
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Extracts session ID from token
        /// </summary>
        /// <param name="token">Token</param>
        /// <returns>Session ID</returns>
        private string ExtractSessionIdFromToken(string token)
        {
            try
            {
                string[] parts = token.Split('.');
                if (parts.Length != 3)
                    return null;

                byte[] payloadBytes = Base64UrlDecode(parts[1]);
                string payloadJson = Encoding.UTF8.GetString(payloadBytes);
                
                var payload = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(payloadJson);
                
                return payload.ContainsKey("sid") ? payload["sid"].ToString() : null;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Base64 URL encoding
        /// </summary>
        /// <param name="input">Input bytes</param>
        /// <returns>Base64 URL encoded string</returns>
        private string Base64UrlEncode(byte[] input)
        {
            return Convert.ToBase64String(input)
                .Replace("+", "-")
                .Replace("/", "_")
                .Replace("=", "");
        }

        /// <summary>
        /// Base64 URL decoding
        /// </summary>
        /// <param name="input">Base64 URL encoded string</param>
        /// <returns>Decoded bytes</returns>
        private byte[] Base64UrlDecode(string input)
        {
            string base64 = input
                .Replace("-", "+")
                .Replace("_", "/");

            // Add padding if needed
            switch (base64.Length % 4)
            {
                case 2: base64 += "=="; break;
                case 3: base64 += "="; break;
            }

            return Convert.FromBase64String(base64);
        }

        /// <summary>
        /// Constant-time string comparison
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
        /// Generates a secret key for token signing
        /// </summary>
        /// <returns>Secret key</returns>
        private string GenerateSecretKey()
        {
            using (var rng = new RNGCryptoServiceProvider())
            {
                byte[] bytes = new byte[64];
                rng.GetBytes(bytes);
                return Convert.ToBase64String(bytes);
            }
        }
    }

    /// <summary>
    /// Session information model
    /// </summary>
    public class SessionInfo
    {
        public string SessionId { get; set; }
        public int UserId { get; set; }
        public string Token { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime ExpiresAt { get; set; }
        public bool IsActive { get; set; }
        public string IpAddress { get; set; }
        public string UserAgent { get; set; }
    }
}
