using NUnit.Framework;
using SafeVault.Security;
using System;
using System.Collections.Generic;

namespace SafeVault.Tests
{
    /// <summary>
    /// Comprehensive test suite for input validation security
    /// Tests for SQL injection, XSS, and other security vulnerabilities
    /// </summary>
    [TestFixture]
    public class TestInputValidation
    {
        [Test]
        public void TestForSQLInjection()
        {
            // Test various SQL injection attack patterns
            var sqlInjectionAttempts = new List<string>
            {
                "'; DROP TABLE Users; --",
                "' OR '1'='1",
                "' OR 1=1 --",
                "admin'--",
                "admin'/*",
                "' UNION SELECT * FROM Users --",
                "'; INSERT INTO Users VALUES ('hacker', 'hacker@evil.com'); --",
                "' OR 'x'='x",
                "') OR ('1'='1",
                "1' OR '1'='1' AND '1'='1",
                "admin' OR '1'='1' --",
                "'; EXEC xp_cmdshell('dir'); --",
                "' OR EXISTS(SELECT * FROM Users WHERE Username='admin') --",
                "admin'; DELETE FROM Users; --",
                "' OR 1=1 LIMIT 1 --"
            };

            foreach (var maliciousInput in sqlInjectionAttempts)
            {
                // Test username validation
                var usernameResult = SecureInputValidator.ValidateUsername(maliciousInput);
                Assert.IsFalse(usernameResult.IsValid, 
                    $"Username validation should reject SQL injection: {maliciousInput}");

                // Test email validation
                var emailResult = SecureInputValidator.ValidateEmail($"{maliciousInput}@test.com");
                Assert.IsFalse(emailResult.IsValid, 
                    $"Email validation should reject SQL injection: {maliciousInput}");

                // Test general text validation
                var textResult = SecureInputValidator.ValidateTextInput(maliciousInput);
                Assert.IsFalse(textResult.IsValid, 
                    $"Text validation should reject SQL injection: {maliciousInput}");
            }
        }

        [Test]
        public void TestForXSS()
        {
            // Test various XSS attack patterns
            var xssAttempts = new List<string>
            {
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')",
                "vbscript:alert('XSS')",
                "<iframe src=javascript:alert('XSS')></iframe>",
                "<body onload=alert('XSS')>",
                "<input onfocus=alert('XSS') autofocus>",
                "<select onfocus=alert('XSS') autofocus>",
                "<textarea onfocus=alert('XSS') autofocus>",
                "<keygen onfocus=alert('XSS') autofocus>",
                "<video><source onerror=alert('XSS')>",
                "<audio src=x onerror=alert('XSS')>",
                "<details open ontoggle=alert('XSS')>",
                "<marquee onstart=alert('XSS')>",
                "<div onmouseover=alert('XSS')>",
                "<a href=javascript:alert('XSS')>Click me</a>",
                "<form><button formaction=javascript:alert('XSS')>",
                "<object data=javascript:alert('XSS')>",
                "<embed src=javascript:alert('XSS')>",
                "<link rel=stylesheet href=javascript:alert('XSS')>",
                "<meta http-equiv=refresh content=0;url=javascript:alert('XSS')>",
                "<style>@import'javascript:alert(\"XSS\")';</style>",
                "<math><mi//xlink:href=\"data:x,<script>alert('XSS')</script>\">",
                "<table background=\"javascript:alert('XSS')\">",
                "<td background=\"javascript:alert('XSS')\">",
                "<th background=\"javascript:alert('XSS')\">",
                "<tr background=\"javascript:alert('XSS')\">",
                "<tbody background=\"javascript:alert('XSS')\">",
                "<tfoot background=\"javascript:alert('XSS')\">",
                "<thead background=\"javascript:alert('XSS')\">",
                "<col background=\"javascript:alert('XSS')\">",
                "<colgroup background=\"javascript:alert('XSS')\">"
            };

            foreach (var maliciousInput in xssAttempts)
            {
                // Test general text validation
                var textResult = SecureInputValidator.ValidateTextInput(maliciousInput);
                Assert.IsFalse(textResult.IsValid, 
                    $"Text validation should reject XSS: {maliciousInput}");

                // Test HTML sanitization
                var sanitized = SecureInputValidator.SanitizeHtml(maliciousInput);
                Assert.IsFalse(sanitized.Contains("<script"), 
                    $"Sanitized HTML should not contain script tags: {maliciousInput}");
                Assert.IsFalse(sanitized.Contains("javascript:"), 
                    $"Sanitized HTML should not contain javascript: protocol: {maliciousInput}");
                Assert.IsFalse(sanitized.Contains("onerror="), 
                    $"Sanitized HTML should not contain onerror attributes: {maliciousInput}");
            }
        }

        [Test]
        public void TestValidInputs()
        {
            // Test valid username inputs
            var validUsernames = new List<string>
            {
                "john_doe",
                "user123",
                "admin",
                "test_user",
                "validuser",
                "User123",
                "a1b2c3"
            };

            foreach (var username in validUsernames)
            {
                var result = SecureInputValidator.ValidateUsername(username);
                Assert.IsTrue(result.IsValid, 
                    $"Valid username should pass validation: {username}");
                Assert.AreEqual(username, result.SanitizedValue, 
                    $"Sanitized username should match input: {username}");
            }

            // Test valid email inputs
            var validEmails = new List<string>
            {
                "user@example.com",
                "test.email@domain.co.uk",
                "user+tag@example.org",
                "firstname.lastname@company.com",
                "user123@test-domain.com"
            };

            foreach (var email in validEmails)
            {
                var result = SecureInputValidator.ValidateEmail(email);
                Assert.IsTrue(result.IsValid, 
                    $"Valid email should pass validation: {email}");
                Assert.AreEqual(email.ToLowerInvariant(), result.SanitizedValue, 
                    $"Sanitized email should match input (lowercase): {email}");
            }
        }

        [Test]
        public void TestInvalidInputs()
        {
            // Test invalid username inputs
            var invalidUsernames = new List<string>
            {
                "", // Empty
                "ab", // Too short
                "a".PadRight(51, 'a'), // Too long
                "user@domain.com", // Contains @
                "user name", // Contains space
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
                "user@name", // Contains at
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
                var result = SecureInputValidator.ValidateUsername(username);
                Assert.IsFalse(result.IsValid, 
                    $"Invalid username should fail validation: {username}");
            }

            // Test invalid email inputs
            var invalidEmails = new List<string>
            {
                "", // Empty
                "invalid-email", // No @
                "@domain.com", // No local part
                "user@", // No domain
                "user@domain", // No TLD
                "user..name@domain.com", // Double dots
                "user@domain..com", // Double dots in domain
                "user@domain.com.", // Trailing dot
                ".user@domain.com", // Leading dot
                "user@.domain.com", // Leading dot in domain
                "user@domain..com", // Double dots in domain
                "user name@domain.com", // Space in local part
                "user@domain name.com", // Space in domain
                "user@domain,com", // Comma in domain
                "user@domain;com", // Semicolon in domain
                "user@domain:com", // Colon in domain
                "user@domain<com", // Less than in domain
                "user@domain>com", // Greater than in domain
                "user@domain[com", // Bracket in domain
                "user@domain]com", // Bracket in domain
                "user@domain{com", // Brace in domain
                "user@domain}com", // Brace in domain
                "user@domain(com", // Parenthesis in domain
                "user@domain)com", // Parenthesis in domain
                "user@domain\"com", // Quote in domain
                "user@domain'com", // Apostrophe in domain
                "user@domain\\com", // Backslash in domain
                "user@domain/com", // Forward slash in domain
                "user@domain|com", // Pipe in domain
                "user@domain*com", // Asterisk in domain
                "user@domain?com", // Question mark in domain
                "user@domain#com", // Hash in domain
                "user@domain%com", // Percent in domain
                "user@domain+com", // Plus in domain
                "user@domain=com", // Equals in domain
                "user@domain!com", // Exclamation in domain
                "user@domain$com", // Dollar in domain
                "user@domain^com", // Caret in domain
                "user@domain~com", // Tilde in domain
                "user@domain`com", // Backtick in domain
                "user@domain,com", // Comma in domain
                "user@domain;com", // Semicolon in domain
                "user@domain:com", // Colon in domain
                "user@domain<com", // Less than in domain
                "user@domain>com", // Greater than in domain
                "user@domain[com", // Bracket in domain
                "user@domain]com", // Bracket in domain
                "user@domain{com", // Brace in domain
                "user@domain}com", // Brace in domain
                "user@domain(com", // Parenthesis in domain
                "user@domain)com", // Parenthesis in domain
                "user@domain\"com", // Quote in domain
                "user@domain'com", // Apostrophe in domain
                "user@domain\\com", // Backslash in domain
                "user@domain/com", // Forward slash in domain
                "user@domain|com", // Pipe in domain
                "user@domain*com", // Asterisk in domain
                "user@domain?com", // Question mark in domain
                "user@domain#com", // Hash in domain
                "user@domain%com", // Percent in domain
                "user@domain+com", // Plus in domain
                "user@domain=com", // Equals in domain
                "user@domain!com", // Exclamation in domain
                "user@domain$com", // Dollar in domain
                "user@domain^com", // Caret in domain
                "user@domain~com", // Tilde in domain
                "user@domain`com" // Backtick in domain
            };

            foreach (var email in invalidEmails)
            {
                var result = SecureInputValidator.ValidateEmail(email);
                Assert.IsFalse(result.IsValid, 
                    $"Invalid email should fail validation: {email}");
            }
        }

        [Test]
        public void TestPasswordValidation()
        {
            // Test valid passwords
            var validPasswords = new List<string>
            {
                "Password123!",
                "MySecure1@Pass",
                "Test123#Word",
                "Valid$Pass1",
                "Strong%Pass2",
                "Good^Pass3",
                "Nice&Pass4",
                "Cool*Pass5",
                "Great+Pass6",
                "Best=Pass7"
            };

            foreach (var password in validPasswords)
            {
                var result = SecureInputValidator.ValidatePassword(password);
                Assert.IsTrue(result.IsValid, 
                    $"Valid password should pass validation: {password}");
            }

            // Test invalid passwords
            var invalidPasswords = new List<string>
            {
                "", // Empty
                "short", // Too short
                "nouppercase123!", // No uppercase
                "NOLOWERCASE123!", // No lowercase
                "NoNumbers!", // No numbers
                "NoSpecialChars123", // No special characters
                "a".PadRight(129, 'a') + "1A!" // Too long
            };

            foreach (var password in invalidPasswords)
            {
                var result = SecureInputValidator.ValidatePassword(password);
                Assert.IsFalse(result.IsValid, 
                    $"Invalid password should fail validation: {password}");
            }
        }

        [Test]
        public void TestHTMLSanitization()
        {
            // Test HTML sanitization
            var testCases = new List<(string input, string expectedContains, string expectedNotContains)>
            {
                ("<script>alert('XSS')</script>", "&lt;script&gt;", "<script>"),
                ("<img src=x onerror=alert('XSS')>", "&lt;img", "onerror="),
                ("javascript:alert('XSS')", "javascript:", "javascript:"),
                ("<a href='javascript:alert(1)'>Click</a>", "&lt;a", "javascript:"),
                ("<div onmouseover='alert(1)'>Hover</div>", "&lt;div", "onmouseover="),
                ("Normal text", "Normal text", "<script>"),
                ("<b>Bold text</b>", "&lt;b&gt;Bold text&lt;/b&gt;", "<b>")
            };

            foreach (var (input, expectedContains, expectedNotContains) in testCases)
            {
                var sanitized = SecureInputValidator.SanitizeHtml(input);
                
                if (!string.IsNullOrEmpty(expectedContains))
                {
                    Assert.IsTrue(sanitized.Contains(expectedContains), 
                        $"Sanitized HTML should contain: {expectedContains}");
                }
                
                if (!string.IsNullOrEmpty(expectedNotContains))
                {
                    Assert.IsFalse(sanitized.Contains(expectedNotContains), 
                        $"Sanitized HTML should not contain: {expectedNotContains}");
                }
            }
        }

        [Test]
        public void TestSaltGeneration()
        {
            // Test salt generation
            var salt1 = SecureInputValidator.GenerateSalt();
            var salt2 = SecureInputValidator.GenerateSalt();
            
            Assert.IsNotNull(salt1, "Salt should not be null");
            Assert.IsNotNull(salt2, "Salt should not be null");
            Assert.AreNotEqual(salt1, salt2, "Generated salts should be different");
            Assert.IsTrue(salt1.Length > 0, "Salt should have length > 0");
            Assert.IsTrue(salt2.Length > 0, "Salt should have length > 0");
        }

        [Test]
        public void TestPasswordHashing()
        {
            // Test password hashing
            var password = "TestPassword123!";
            var salt = SecureInputValidator.GenerateSalt();
            
            var hash1 = SecureInputValidator.HashPassword(password, salt);
            var hash2 = SecureInputValidator.HashPassword(password, salt);
            
            Assert.IsNotNull(hash1, "Hash should not be null");
            Assert.IsNotNull(hash2, "Hash should not be null");
            Assert.AreEqual(hash1, hash2, "Same password and salt should produce same hash");
            Assert.AreNotEqual(password, hash1, "Hash should not equal original password");
            Assert.IsTrue(hash1.Length > 0, "Hash should have length > 0");
            
            // Test with different salt
            var differentSalt = SecureInputValidator.GenerateSalt();
            var hash3 = SecureInputValidator.HashPassword(password, differentSalt);
            
            Assert.AreNotEqual(hash1, hash3, "Different salts should produce different hashes");
        }

        [Test]
        public void TestEdgeCases()
        {
            // Test null and empty inputs
            Assert.IsFalse(SecureInputValidator.ValidateUsername(null).IsValid);
            Assert.IsFalse(SecureInputValidator.ValidateUsername("").IsValid);
            Assert.IsFalse(SecureInputValidator.ValidateUsername("   ").IsValid);
            
            Assert.IsFalse(SecureInputValidator.ValidateEmail(null).IsValid);
            Assert.IsFalse(SecureInputValidator.ValidateEmail("").IsValid);
            Assert.IsFalse(SecureInputValidator.ValidateEmail("   ").IsValid);
            
            Assert.IsFalse(SecureInputValidator.ValidatePassword(null).IsValid);
            Assert.IsFalse(SecureInputValidator.ValidatePassword("").IsValid);
            Assert.IsFalse(SecureInputValidator.ValidatePassword("   ").IsValid);
            
            // Test very long inputs
            var longString = new string('a', 1000);
            var result = SecureInputValidator.ValidateTextInput(longString, 500);
            Assert.IsFalse(result.IsValid, "Very long input should fail validation");
            
            // Test Unicode and special characters
            var unicodeInput = "用户@测试.com";
            var unicodeResult = SecureInputValidator.ValidateEmail(unicodeInput);
            Assert.IsFalse(unicodeResult.IsValid, "Unicode email should fail validation");
        }
    }
}
