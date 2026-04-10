using System;
using System.Threading.Tasks;
using SafeVault.Data;

namespace SafeVault.Services
{
    /// <summary>
    /// Audit logging service for security events
    /// </summary>
    public class AuditLogger
    {
        private readonly SecureDatabaseManager _dbManager;

        public AuditLogger(SecureDatabaseManager dbManager)
        {
            _dbManager = dbManager ?? throw new ArgumentNullException(nameof(dbManager));
        }

        /// <summary>
        /// Logs an audit event
        /// </summary>
        /// <param name="userId">User ID (nullable)</param>
        /// <param name="action">Action performed</param>
        /// <param name="details">Action details</param>
        /// <param name="ipAddress">Client IP address</param>
        /// <param name="userAgent">Client user agent</param>
        public async Task LogAsync(int? userId, string action, string details, string ipAddress, string userAgent)
        {
            try
            {
                await _dbManager.LogAuditEventAsync(userId, action, details, ipAddress, userAgent);
            }
            catch
            {
                // Log error but don't throw to avoid breaking the main operation
                // In production, use proper logging framework
            }
        }
    }
}
