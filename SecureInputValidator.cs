using System;
using System.Text.RegularExpressions;
using System.Web;
using System.Security.Cryptography;
using System.Text;

namespace SafeVault.Security
{
    /// <summary>
    /// Secure input validation class to prevent XSS, SQL injection, and other attacks
    /// </summary>
    public class SecureInputValidator
    {
        // Regular expressions for validation
        private static readonly Regex UsernameRegex = new Regex(@"^[a-zA-Z0-9_]{3,50}$", RegexOptions.Compiled);
        private static readonly Regex EmailRegex = new Regex(@"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", RegexOptions.Compiled);
        private static readonly Regex SafeStringRegex = new Regex(@"^[a-zA-Z0-9\s._-]+$", RegexOptions.Compiled);
        
        // Dangerous patterns to detect and block
        private static readonly string[] DangerousPatterns = {
            @"<script[^>]*>.*?</script>",
            @"javascript:",
            @"vbscript:",
            @"onload\s*=",
            @"onerror\s*=",
            @"onclick\s*=",
            @"onmouseover\s*=",
            @"';\s*drop\s+table",
            @"';\s*delete\s+from",
            @"';\s*insert\s+into",
            @"';\s*update\s+set",
            @"union\s+select",
            @"or\s+1\s*=\s*1",
            @"and\s+1\s*=\s*1",
            @"exec\s*\(",
            @"sp_executesql",
            @"xp_cmdshell"
        };

        /// <summary>
        /// Validates and sanitizes username input
        /// </summary>
        /// <param name="username">Raw username input</param>
        /// <returns>Validation result with sanitized username</returns>
        public static ValidationResult ValidateUsername(string username)
        {
            var result = new ValidationResult();
            
            if (string.IsNullOrWhiteSpace(username))
            {
                result.IsValid = false;
                result.ErrorMessage = "Username cannot be empty";
                return result;
            }

            // Trim whitespace
            username = username.Trim();

            // Check length
            if (username.Length < 3 || username.Length > 50)
            {
                result.IsValid = false;
                result.ErrorMessage = "Username must be between 3 and 50 characters";
                return result;
            }

            // Check for dangerous patterns
            if (ContainsDangerousPatterns(username))
            {
                result.IsValid = false;
                result.ErrorMessage = "Username contains invalid characters or patterns";
                return result;
            }

            // Validate format
            if (!UsernameRegex.IsMatch(username))
            {
                result.IsValid = false;
                result.ErrorMessage = "Username can only contain letters, numbers, and underscores";
                return result;
            }

            result.IsValid = true;
            result.SanitizedValue = username;
            return result;
        }

        /// <summary>
        /// Validates and sanitizes email input
        /// </summary>
        /// <param name="email">Raw email input</param>
        /// <returns>Validation result with sanitized email</returns>
        public static ValidationResult ValidateEmail(string email)
        {
            var result = new ValidationResult();
            
            if (string.IsNullOrWhiteSpace(email))
            {
                result.IsValid = false;
                result.ErrorMessage = "Email cannot be empty";
                return result;
            }

            // Trim whitespace
            email = email.Trim().ToLowerInvariant();

            // Check length
            if (email.Length > 254) // RFC 5321 limit
            {
                result.IsValid = false;
                result.ErrorMessage = "Email address is too long";
                return result;
            }

            // Check for dangerous patterns
            if (ContainsDangerousPatterns(email))
            {
                result.IsValid = false;
                result.ErrorMessage = "Email contains invalid characters or patterns";
                return result;
            }

            // Validate format
            if (!EmailRegex.IsMatch(email))
            {
                result.IsValid = false;
                result.ErrorMessage = "Please enter a valid email address";
                return result;
            }

            result.IsValid = true;
            result.SanitizedValue = email;
            return result;
        }

        /// <summary>
        /// Sanitizes HTML content to prevent XSS attacks
        /// </summary>
        /// <param name="input">Raw HTML input</param>
        /// <returns>Sanitized HTML</returns>
        public static string SanitizeHtml(string input)
        {
            if (string.IsNullOrEmpty(input))
                return string.Empty;

            // HTML encode the input
            string sanitized = HttpUtility.HtmlEncode(input);
            
            // Additional sanitization for common XSS patterns
            sanitized = Regex.Replace(sanitized, @"javascript:", "", RegexOptions.IgnoreCase);
            sanitized = Regex.Replace(sanitized, @"vbscript:", "", RegexOptions.IgnoreCase);
            sanitized = Regex.Replace(sanitized, @"on\w+\s*=", "", RegexOptions.IgnoreCase);
            
            return sanitized;
        }

        /// <summary>
        /// Validates and sanitizes general text input
        /// </summary>
        /// <param name="input">Raw text input</param>
        /// <param name="maxLength">Maximum allowed length</param>
        /// <returns>Validation result with sanitized text</returns>
        public static ValidationResult ValidateTextInput(string input, int maxLength = 1000)
        {
            var result = new ValidationResult();
            
            if (string.IsNullOrWhiteSpace(input))
            {
                result.IsValid = false;
                result.ErrorMessage = "Input cannot be empty";
                return result;
            }

            // Trim whitespace
            input = input.Trim();

            // Check length
            if (input.Length > maxLength)
            {
                result.IsValid = false;
                result.ErrorMessage = $"Input cannot exceed {maxLength} characters";
                return result;
            }

            // Check for dangerous patterns
            if (ContainsDangerousPatterns(input))
            {
                result.IsValid = false;
                result.ErrorMessage = "Input contains potentially dangerous content";
                return result;
            }

            result.IsValid = true;
            result.SanitizedValue = SanitizeHtml(input);
            return result;
        }

        /// <summary>
        /// Checks if input contains dangerous patterns
        /// </summary>
        /// <param name="input">Input to check</param>
        /// <returns>True if dangerous patterns are found</returns>
        private static bool ContainsDangerousPatterns(string input)
        {
            if (string.IsNullOrEmpty(input))
                return false;

            string lowerInput = input.ToLowerInvariant();
            
            foreach (string pattern in DangerousPatterns)
            {
                if (Regex.IsMatch(lowerInput, pattern, RegexOptions.IgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Generates a secure random salt for password hashing
        /// </summary>
        /// <param name="length">Length of the salt in bytes</param>
        /// <returns>Base64 encoded salt</returns>
        public static string GenerateSalt(int length = 32)
        {
            using (var rng = new RNGCryptoServiceProvider())
            {
                byte[] saltBytes = new byte[length];
                rng.GetBytes(saltBytes);
                return Convert.ToBase64String(saltBytes);
            }
        }

        /// <summary>
        /// Hashes a password with salt using PBKDF2
        /// </summary>
        /// <param name="password">Plain text password</param>
        /// <param name="salt">Salt for hashing</param>
        /// <returns>Hashed password</returns>
        public static string HashPassword(string password, string salt)
        {
            if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(salt))
                throw new ArgumentException("Password and salt cannot be null or empty");

            byte[] saltBytes = Convert.FromBase64String(salt);
            
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, saltBytes, 10000, HashAlgorithmName.SHA256))
            {
                byte[] hashBytes = pbkdf2.GetBytes(32);
                return Convert.ToBase64String(hashBytes);
            }
        }

        /// <summary>
        /// Validates password strength
        /// </summary>
        /// <param name="password">Password to validate</param>
        /// <returns>Validation result</returns>
        public static ValidationResult ValidatePassword(string password)
        {
            var result = new ValidationResult();
            
            if (string.IsNullOrEmpty(password))
            {
                result.IsValid = false;
                result.ErrorMessage = "Password cannot be empty";
                return result;
            }

            if (password.Length < 8)
            {
                result.IsValid = false;
                result.ErrorMessage = "Password must be at least 8 characters long";
                return result;
            }

            if (password.Length > 128)
            {
                result.IsValid = false;
                result.ErrorMessage = "Password cannot exceed 128 characters";
                return result;
            }

            // Check for at least one uppercase letter
            if (!Regex.IsMatch(password, @"[A-Z]"))
            {
                result.IsValid = false;
                result.ErrorMessage = "Password must contain at least one uppercase letter";
                return result;
            }

            // Check for at least one lowercase letter
            if (!Regex.IsMatch(password, @"[a-z]"))
            {
                result.IsValid = false;
                result.ErrorMessage = "Password must contain at least one lowercase letter";
                return result;
            }

            // Check for at least one digit
            if (!Regex.IsMatch(password, @"[0-9]"))
            {
                result.IsValid = false;
                result.ErrorMessage = "Password must contain at least one digit";
                return result;
            }

            // Check for at least one special character
            if (!Regex.IsMatch(password, @"[!@#$%^&*()_+\-=\[\]{};':""\\|,.<>\/?]"))
            {
                result.IsValid = false;
                result.ErrorMessage = "Password must contain at least one special character";
                return result;
            }

            result.IsValid = true;
            result.SanitizedValue = password; // Don't sanitize passwords, just validate
            return result;
        }
    }

    /// <summary>
    /// Result of input validation
    /// </summary>
    public class ValidationResult
    {
        public bool IsValid { get; set; }
        public string SanitizedValue { get; set; }
        public string ErrorMessage { get; set; }
    }
}
