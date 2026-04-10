using NUnit.Framework;
using SafeVault.Controllers;
using SafeVault.Security;
using System;
using System.Threading.Tasks;
using System.Web.Http;
using System.Net.Http;
using System.Web.Http.Hosting;
using System.Web.Http.Controllers;
using System.Web.Http.Routing;
using System.Collections.Generic;
using System.Net;

namespace SafeVault.Tests
{
    /// <summary>
    /// Comprehensive test suite for API security
    /// Tests for XSS, SQL injection, and other security vulnerabilities in API endpoints
    /// </summary>
    [TestFixture]
    public class TestAPISecurity
    {
        private UserController _controller;
        private HttpConfiguration _config;

        [SetUp]
        public void Setup()
        {
            _config = new HttpConfiguration();
            _controller = new UserController();
            _controller.Request = new HttpRequestMessage();
            _controller.Request.Properties.Add(HttpPropertyKeys.HttpConfigurationKey, _config);
        }

        [TearDown]
        public void TearDown()
        {
            _controller?.Dispose();
        }

        [Test]
        public async Task TestXSSPrevention_CreateUser()
        {
            // Test XSS attempts in user creation
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

            foreach (var xssPayload in xssAttempts)
            {
                try
                {
                    var request = new CreateUserRequest
                    {
                        Username = xssPayload,
                        Email = $"{xssPayload}@example.com",
                        Password = "ValidPass123!"
                    };

                    var result = await _controller.CreateUser(request);
                    
                    // XSS attempts should be rejected by validation
                    Assert.IsInstanceOf<BadRequestResult>(result) || Assert.IsInstanceOf<InvalidModelStateResult>(result),
                        $"XSS attempt should be rejected: {xssPayload}");
                }
                catch (Exception ex)
                {
                    // Any exception indicates the XSS was properly blocked
                    Assert.IsTrue(ex.Message.Contains("validation") || ex.Message.Contains("Invalid"), 
                        $"XSS attempt should be blocked: {xssPayload}");
                }
            }
        }

        [Test]
        public async Task TestSQLInjectionPrevention_CreateUser()
        {
            // Test SQL injection attempts in user creation
            var sqlInjectionAttempts = new List<string>
            {
                "admin'; DROP TABLE Users; --",
                "user' OR '1'='1",
                "test'; INSERT INTO Users VALUES ('hacker', 'hacker@evil.com', 'hash', 'salt'); --",
                "victim'; UPDATE Users SET Username='hacked' WHERE Username='admin'; --",
                "target'; DELETE FROM Users; --",
                "user' UNION SELECT * FROM Users --",
                "admin' OR EXISTS(SELECT * FROM Users WHERE Username='admin') --",
                "test'; EXEC xp_cmdshell('dir'); --",
                "user' OR 1=1 LIMIT 1 --",
                "admin'/*",
                "user'--",
                "test' OR 'x'='x",
                "admin') OR ('1'='1",
                "user' OR 1=1 AND '1'='1",
                "test' OR '1'='1' --",
                "admin'; SELECT * FROM Users; --"
            };

            foreach (var sqlPayload in sqlInjectionAttempts)
            {
                try
                {
                    var request = new CreateUserRequest
                    {
                        Username = sqlPayload,
                        Email = $"{sqlPayload}@example.com",
                        Password = "ValidPass123!"
                    };

                    var result = await _controller.CreateUser(request);
                    
                    // SQL injection attempts should be rejected by validation
                    Assert.IsInstanceOf<BadRequestResult>(result) || Assert.IsInstanceOf<InvalidModelStateResult>(result),
                        $"SQL injection attempt should be rejected: {sqlPayload}");
                }
                catch (Exception ex)
                {
                    // Any exception indicates the SQL injection was properly blocked
                    Assert.IsTrue(ex.Message.Contains("validation") || ex.Message.Contains("Invalid"), 
                        $"SQL injection attempt should be blocked: {sqlPayload}");
                }
            }
        }

        [Test]
        public async Task TestXSSPrevention_Authentication()
        {
            // Test XSS attempts in authentication
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

            foreach (var xssPayload in xssAttempts)
            {
                try
                {
                    var request = new AuthenticateUserRequest
                    {
                        Username = xssPayload,
                        Password = "ValidPass123!"
                    };

                    var result = await _controller.AuthenticateUser(request);
                    
                    // XSS attempts should be rejected by validation
                    Assert.IsInstanceOf<BadRequestResult>(result) || Assert.IsInstanceOf<InvalidModelStateResult>(result),
                        $"XSS attempt should be rejected: {xssPayload}");
                }
                catch (Exception ex)
                {
                    // Any exception indicates the XSS was properly blocked
                    Assert.IsTrue(ex.Message.Contains("validation") || ex.Message.Contains("Invalid"), 
                        $"XSS attempt should be blocked: {xssPayload}");
                }
            }
        }

        [Test]
        public async Task TestSQLInjectionPrevention_Authentication()
        {
            // Test SQL injection attempts in authentication
            var sqlInjectionAttempts = new List<string>
            {
                "admin' OR '1'='1",
                "user' OR 1=1 --",
                "test' OR EXISTS(SELECT * FROM Users WHERE Username='admin') --",
                "victim' OR 'x'='x",
                "target' OR 1=1 LIMIT 1 --",
                "admin'/*",
                "user'--",
                "test') OR ('1'='1",
                "admin' OR 1=1 AND '1'='1",
                "user' OR '1'='1' --"
            };

            foreach (var sqlPayload in sqlInjectionAttempts)
            {
                try
                {
                    var request = new AuthenticateUserRequest
                    {
                        Username = sqlPayload,
                        Password = "ValidPass123!"
                    };

                    var result = await _controller.AuthenticateUser(request);
                    
                    // SQL injection attempts should be rejected by validation
                    Assert.IsInstanceOf<BadRequestResult>(result) || Assert.IsInstanceOf<InvalidModelStateResult>(result),
                        $"SQL injection attempt should be rejected: {sqlPayload}");
                }
                catch (Exception ex)
                {
                    // Any exception indicates the SQL injection was properly blocked
                    Assert.IsTrue(ex.Message.Contains("validation") || ex.Message.Contains("Invalid"), 
                        $"SQL injection attempt should be blocked: {sqlPayload}");
                }
            }
        }

        [Test]
        public async Task TestXSSPrevention_SearchUsers()
        {
            // Test XSS attempts in user search
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

            foreach (var xssPayload in xssAttempts)
            {
                try
                {
                    var result = await _controller.SearchUsers(xssPayload, 10);
                    
                    // XSS attempts should be rejected by validation
                    Assert.IsInstanceOf<BadRequestResult>(result) || Assert.IsInstanceOf<InvalidModelStateResult>(result),
                        $"XSS attempt should be rejected: {xssPayload}");
                }
                catch (Exception ex)
                {
                    // Any exception indicates the XSS was properly blocked
                    Assert.IsTrue(ex.Message.Contains("validation") || ex.Message.Contains("Invalid"), 
                        $"XSS attempt should be blocked: {xssPayload}");
                }
            }
        }

        [Test]
        public async Task TestSQLInjectionPrevention_SearchUsers()
        {
            // Test SQL injection attempts in user search
            var sqlInjectionAttempts = new List<string>
            {
                "admin'; DROP TABLE Users; --",
                "user' OR '1'='1",
                "test'; INSERT INTO Users VALUES ('hacker', 'hacker@evil.com', 'hash', 'salt'); --",
                "victim'; UPDATE Users SET Username='hacked' WHERE Username='admin'; --",
                "target'; DELETE FROM Users; --",
                "user' UNION SELECT * FROM Users --",
                "admin' OR EXISTS(SELECT * FROM Users WHERE Username='admin') --",
                "test'; EXEC xp_cmdshell('dir'); --",
                "user' OR 1=1 LIMIT 1 --",
                "admin'/*",
                "user'--",
                "test' OR 'x'='x",
                "admin') OR ('1'='1",
                "user' OR 1=1 AND '1'='1",
                "test' OR '1'='1' --",
                "admin'; SELECT * FROM Users; --"
            };

            foreach (var sqlPayload in sqlInjectionAttempts)
            {
                try
                {
                    var result = await _controller.SearchUsers(sqlPayload, 10);
                    
                    // SQL injection attempts should be rejected by validation
                    Assert.IsInstanceOf<BadRequestResult>(result) || Assert.IsInstanceOf<InvalidModelStateResult>(result),
                        $"SQL injection attempt should be rejected: {sqlPayload}");
                }
                catch (Exception ex)
                {
                    // Any exception indicates the SQL injection was properly blocked
                    Assert.IsTrue(ex.Message.Contains("validation") || ex.Message.Contains("Invalid"), 
                        $"SQL injection attempt should be blocked: {sqlPayload}");
                }
            }
        }

        [Test]
        public async Task TestInputValidation_CreateUser()
        {
            // Test various invalid inputs for user creation
            var invalidInputs = new List<(string username, string email, string password)>
            {
                ("", "test@example.com", "ValidPass123!"), // Empty username
                ("validuser", "", "ValidPass123!"), // Empty email
                ("validuser", "test@example.com", ""), // Empty password
                (null, "test@example.com", "ValidPass123!"), // Null username
                ("validuser", null, "ValidPass123!"), // Null email
                ("validuser", "test@example.com", null), // Null password
                ("ab", "test@example.com", "ValidPass123!"), // Too short username
                ("validuser", "invalid-email", "ValidPass123!"), // Invalid email
                ("validuser", "test@example.com", "short"), // Too short password
                ("validuser", "test@example.com", "nouppercase123!"), // No uppercase password
                ("validuser", "test@example.com", "NOLOWERCASE123!"), // No lowercase password
                ("validuser", "test@example.com", "NoNumbers!"), // No numbers password
                ("validuser", "test@example.com", "NoSpecialChars123"), // No special chars password
                ("a".PadRight(51, 'a'), "test@example.com", "ValidPass123!"), // Too long username
                ("validuser", "test@example.com", "a".PadRight(129, 'a') + "1A!") // Too long password
            };

            foreach (var (username, email, password) in invalidInputs)
            {
                try
                {
                    var request = new CreateUserRequest
                    {
                        Username = username,
                        Email = email,
                        Password = password
                    };

                    var result = await _controller.CreateUser(request);
                    
                    // Invalid inputs should be rejected
                    Assert.IsInstanceOf<BadRequestResult>(result) || Assert.IsInstanceOf<InvalidModelStateResult>(result),
                        $"Invalid input should be rejected: {username}, {email}, {password}");
                }
                catch (Exception ex)
                {
                    // Any exception indicates the invalid input was properly blocked
                    Assert.IsTrue(ex.Message.Contains("validation") || ex.Message.Contains("Invalid"), 
                        $"Invalid input should be blocked: {username}, {email}, {password}");
                }
            }
        }

        [Test]
        public async Task TestInputValidation_Authentication()
        {
            // Test various invalid inputs for authentication
            var invalidInputs = new List<(string username, string password)>
            {
                ("", "ValidPass123!"), // Empty username
                ("validuser", ""), // Empty password
                (null, "ValidPass123!"), // Null username
                ("validuser", null), // Null password
                ("ab", "ValidPass123!"), // Too short username
                ("validuser", "short"), // Too short password
                ("validuser", "nouppercase123!"), // No uppercase password
                ("validuser", "NOLOWERCASE123!"), // No lowercase password
                ("validuser", "NoNumbers!"), // No numbers password
                ("validuser", "NoSpecialChars123"), // No special chars password
                ("a".PadRight(51, 'a'), "ValidPass123!"), // Too long username
                ("validuser", "a".PadRight(129, 'a') + "1A!") // Too long password
            };

            foreach (var (username, password) in invalidInputs)
            {
                try
                {
                    var request = new AuthenticateUserRequest
                    {
                        Username = username,
                        Password = password
                    };

                    var result = await _controller.AuthenticateUser(request);
                    
                    // Invalid inputs should be rejected
                    Assert.IsInstanceOf<BadRequestResult>(result) || Assert.IsInstanceOf<InvalidModelStateResult>(result),
                        $"Invalid input should be rejected: {username}, {password}");
                }
                catch (Exception ex)
                {
                    // Any exception indicates the invalid input was properly blocked
                    Assert.IsTrue(ex.Message.Contains("validation") || ex.Message.Contains("Invalid"), 
                        $"Invalid input should be blocked: {username}, {password}");
                }
            }
        }

        [Test]
        public async Task TestInputValidation_SearchUsers()
        {
            // Test various invalid inputs for user search
            var invalidInputs = new List<string>
            {
                "", // Empty search term
                null, // Null search term
                "   ", // Whitespace only
                "a".PadRight(101, 'a'), // Too long search term
                "<script>alert('XSS')</script>", // XSS attempt
                "admin'; DROP TABLE Users; --", // SQL injection attempt
                "user' OR '1'='1", // SQL injection attempt
                "test'; INSERT INTO Users VALUES ('hacker', 'hacker@evil.com', 'hash', 'salt'); --", // SQL injection attempt
                "victim'; UPDATE Users SET Username='hacked' WHERE Username='admin'; --", // SQL injection attempt
                "target'; DELETE FROM Users; --", // SQL injection attempt
                "user' UNION SELECT * FROM Users --", // SQL injection attempt
                "admin' OR EXISTS(SELECT * FROM Users WHERE Username='admin') --", // SQL injection attempt
                "test'; EXEC xp_cmdshell('dir'); --", // SQL injection attempt
                "user' OR 1=1 LIMIT 1 --", // SQL injection attempt
                "admin'/*", // SQL injection attempt
                "user'--", // SQL injection attempt
                "test' OR 'x'='x", // SQL injection attempt
                "admin') OR ('1'='1", // SQL injection attempt
                "user' OR 1=1 AND '1'='1", // SQL injection attempt
                "test' OR '1'='1' --", // SQL injection attempt
                "admin'; SELECT * FROM Users; --" // SQL injection attempt
            };

            foreach (var searchTerm in invalidInputs)
            {
                try
                {
                    var result = await _controller.SearchUsers(searchTerm, 10);
                    
                    // Invalid inputs should be rejected
                    Assert.IsInstanceOf<BadRequestResult>(result) || Assert.IsInstanceOf<InvalidModelStateResult>(result),
                        $"Invalid search term should be rejected: {searchTerm}");
                }
                catch (Exception ex)
                {
                    // Any exception indicates the invalid input was properly blocked
                    Assert.IsTrue(ex.Message.Contains("validation") || ex.Message.Contains("Invalid"), 
                        $"Invalid search term should be blocked: {searchTerm}");
                }
            }
        }

        [Test]
        public async Task TestInputValidation_GetUser()
        {
            // Test various invalid inputs for user retrieval
            var invalidInputs = new List<int>
            {
                -1, // Negative ID
                0, // Zero ID
                int.MinValue, // Minimum integer value
                int.MaxValue // Maximum integer value
            };

            foreach (var userId in invalidInputs)
            {
                try
                {
                    var result = await _controller.GetUser(userId);
                    
                    // Invalid inputs should be rejected
                    Assert.IsInstanceOf<BadRequestResult>(result) || Assert.IsInstanceOf<InvalidModelStateResult>(result),
                        $"Invalid user ID should be rejected: {userId}");
                }
                catch (Exception ex)
                {
                    // Any exception indicates the invalid input was properly blocked
                    Assert.IsTrue(ex.Message.Contains("validation") || ex.Message.Contains("Invalid"), 
                        $"Invalid user ID should be blocked: {userId}");
                }
            }
        }

        [Test]
        public async Task TestInputValidation_SearchUsersLimit()
        {
            // Test various invalid limits for user search
            var invalidLimits = new List<int>
            {
                -1, // Negative limit
                0, // Zero limit
                -100, // Large negative limit
                1000, // Too large limit
                int.MinValue, // Minimum integer value
                int.MaxValue // Maximum integer value
            };

            foreach (var limit in invalidLimits)
            {
                try
                {
                    var result = await _controller.SearchUsers("validsearch", limit);
                    
                    // Invalid limits should be rejected or clamped to valid range
                    Assert.IsInstanceOf<BadRequestResult>(result) || Assert.IsInstanceOf<InvalidModelStateResult>(result),
                        $"Invalid limit should be rejected: {limit}");
                }
                catch (Exception ex)
                {
                    // Any exception indicates the invalid input was properly blocked
                    Assert.IsTrue(ex.Message.Contains("validation") || ex.Message.Contains("Invalid"), 
                        $"Invalid limit should be blocked: {limit}");
                }
            }
        }

        [Test]
        public async Task TestHealthCheck()
        {
            // Test health check endpoint
            var result = await _controller.HealthCheck();
            
            // Health check should always succeed
            Assert.IsInstanceOf<OkNegotiatedContentResult<HealthCheckResponse>>(result),
                "Health check should succeed");
        }

        [Test]
        public async Task TestConcurrentRequests()
        {
            // Test concurrent API requests to ensure thread safety
            var tasks = new List<Task>();
            
            for (int i = 0; i < 10; i++)
            {
                int index = i;
                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        var request = new CreateUserRequest
                        {
                            Username = $"concurrentuser{index}",
                            Email = $"concurrent{index}@example.com",
                            Password = "ValidPass123!"
                        };

                        var result = await _controller.CreateUser(request);
                        
                        // Concurrent requests should be handled properly
                        Assert.IsNotNull(result, $"Concurrent request should be handled: {index}");
                    }
                    catch (Exception ex)
                    {
                        // Any exception indicates a potential thread safety issue
                        Assert.Fail($"Concurrent request failed: {index}, {ex.Message}");
                    }
                }));
            }

            await Task.WhenAll(tasks);
        }

        [Test]
        public async Task TestErrorHandling()
        {
            // Test error handling for various scenarios
            try
            {
                // Test with null request
                var result = await _controller.CreateUser(null);
                
                // Null request should be rejected
                Assert.IsInstanceOf<BadRequestResult>(result) || Assert.IsInstanceOf<InvalidModelStateResult>(result),
                    "Null request should be rejected");
            }
            catch (Exception ex)
            {
                // Any exception indicates the null request was properly handled
                Assert.IsTrue(ex.Message.Contains("null") || ex.Message.Contains("Null"), 
                    $"Null request should be handled: {ex.Message}");
            }

            try
            {
                // Test with null authentication request
                var result = await _controller.AuthenticateUser(null);
                
                // Null request should be rejected
                Assert.IsInstanceOf<BadRequestResult>(result) || Assert.IsInstanceOf<InvalidModelStateResult>(result),
                    "Null authentication request should be rejected");
            }
            catch (Exception ex)
            {
                // Any exception indicates the null request was properly handled
                Assert.IsTrue(ex.Message.Contains("null") || ex.Message.Contains("Null"), 
                    $"Null authentication request should be handled: {ex.Message}");
            }
        }
    }
}
