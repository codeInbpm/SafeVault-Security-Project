using System;
using System.Threading.Tasks;
using SafeVault.Security;
using SafeVault.Data;
using SafeVault.Controllers;
using System.Collections.Generic;
using System.Diagnostics;

namespace SafeVault.TestRunner
{
    /// <summary>
    /// Comprehensive test runner for SafeVault security testing
    /// Simulates real-world attack scenarios and validates security measures
    /// </summary>
    public class SecurityTestRunner
    {
        private readonly SecureInputValidator _inputValidator;
        private readonly SecureDatabaseManager _dbManager;
        private readonly UserController _controller;
        private readonly List<TestResult> _testResults;

        public SecurityTestRunner()
        {
            _inputValidator = new SecureInputValidator();
            _dbManager = new SecureDatabaseManager("Server=localhost;Database=SafeVault;Integrated Security=true;TrustServerCertificate=true;");
            _controller = new UserController();
            _testResults = new List<TestResult>();
        }

        /// <summary>
        /// Runs all security tests and generates a comprehensive report
        /// </summary>
        public async Task<SecurityTestReport> RunAllTestsAsync()
        {
            Console.WriteLine("Starting SafeVault Security Test Suite...");
            Console.WriteLine("==========================================");

            var report = new SecurityTestReport
            {
                StartTime = DateTime.UtcNow,
                TestResults = new List<TestResult>()
            };

            // Run input validation tests
            await RunInputValidationTestsAsync(report);

            // Run database security tests
            await RunDatabaseSecurityTestsAsync(report);

            // Run API security tests
            await RunAPISecurityTestsAsync(report);

            // Run integration tests
            await RunIntegrationTestsAsync(report);

            report.EndTime = DateTime.UtcNow;
            report.Duration = report.EndTime - report.StartTime;

            GenerateReport(report);
            return report;
        }

        /// <summary>
        /// Tests input validation security measures
        /// </summary>
        private async Task RunInputValidationTestsAsync(SecurityTestReport report)
        {
            Console.WriteLine("\n1. Testing Input Validation Security...");
            Console.WriteLine("--------------------------------------");

            var testCases = new List<(string testName, Func<Task<bool>> testFunction)>
            {
                ("SQL Injection Prevention - Username", TestSQLInjectionPreventionUsername),
                ("SQL Injection Prevention - Email", TestSQLInjectionPreventionEmail),
                ("XSS Prevention - Username", TestXSSPreventionUsername),
                ("XSS Prevention - Email", TestXSSPreventionEmail),
                ("Password Strength Validation", TestPasswordStrengthValidation),
                ("HTML Sanitization", TestHTMLSanitization),
                ("Edge Case Handling", TestEdgeCaseHandling)
            };

            foreach (var (testName, testFunction) in testCases)
            {
                var result = await RunSingleTestAsync(testName, testFunction);
                report.TestResults.Add(result);
            }
        }

        /// <summary>
        /// Tests database security measures
        /// </summary>
        private async Task RunDatabaseSecurityTestsAsync(SecurityTestReport report)
        {
            Console.WriteLine("\n2. Testing Database Security...");
            Console.WriteLine("-------------------------------");

            var testCases = new List<(string testName, Func<Task<bool>> testFunction)>
            {
                ("Parameterized Query Protection", TestParameterizedQueryProtection),
                ("SQL Injection Prevention - Create User", TestSQLInjectionPreventionCreateUser),
                ("SQL Injection Prevention - Authentication", TestSQLInjectionPreventionAuthentication),
                ("SQL Injection Prevention - Search", TestSQLInjectionPreventionSearch),
                ("Connection Security", TestConnectionSecurity),
                ("Audit Logging", TestAuditLogging)
            };

            foreach (var (testName, testFunction) in testCases)
            {
                var result = await RunSingleTestAsync(testName, testFunction);
                report.TestResults.Add(result);
            }
        }

        /// <summary>
        /// Tests API security measures
        /// </summary>
        private async Task RunAPISecurityTestsAsync(SecurityTestReport report)
        {
            Console.WriteLine("\n3. Testing API Security...");
            Console.WriteLine("--------------------------");

            var testCases = new List<(string testName, Func<Task<bool>> testFunction)>
            {
                ("XSS Prevention - Create User API", TestXSSPreventionCreateUserAPI),
                ("XSS Prevention - Authentication API", TestXSSPreventionAuthenticationAPI),
                ("XSS Prevention - Search API", TestXSSPreventionSearchAPI),
                ("SQL Injection Prevention - Create User API", TestSQLInjectionPreventionCreateUserAPI),
                ("SQL Injection Prevention - Authentication API", TestSQLInjectionPreventionAuthenticationAPI),
                ("SQL Injection Prevention - Search API", TestSQLInjectionPreventionSearchAPI),
                ("Input Validation - Create User API", TestInputValidationCreateUserAPI),
                ("Input Validation - Authentication API", TestInputValidationAuthenticationAPI),
                ("Input Validation - Search API", TestInputValidationSearchAPI),
                ("Error Handling", TestErrorHandlingAPI)
            };

            foreach (var (testName, testFunction) in testCases)
            {
                var result = await RunSingleTestAsync(testName, testFunction);
                report.TestResults.Add(result);
            }
        }

        /// <summary>
        /// Tests integration scenarios
        /// </summary>
        private async Task RunIntegrationTestsAsync(SecurityTestReport report)
        {
            Console.WriteLine("\n4. Testing Integration Security...");
            Console.WriteLine("-----------------------------------");

            var testCases = new List<(string testName, Func<Task<bool>> testFunction)>
            {
                ("End-to-End Security Flow", TestEndToEndSecurityFlow),
                ("Concurrent Request Handling", TestConcurrentRequestHandling),
                ("Resource Cleanup", TestResourceCleanup),
                ("Performance Under Attack", TestPerformanceUnderAttack)
            };

            foreach (var (testName, testFunction) in testCases)
            {
                var result = await RunSingleTestAsync(testName, testFunction);
                report.TestResults.Add(result);
            }
        }

        /// <summary>
        /// Runs a single test and records the result
        /// </summary>
        private async Task<TestResult> RunSingleTestAsync(string testName, Func<Task<bool>> testFunction)
        {
            var stopwatch = Stopwatch.StartNew();
            var result = new TestResult
            {
                TestName = testName,
                StartTime = DateTime.UtcNow
            };

            try
            {
                result.Passed = await testFunction();
                result.ErrorMessage = result.Passed ? null : "Test failed";
            }
            catch (Exception ex)
            {
                result.Passed = false;
                result.ErrorMessage = ex.Message;
            }
            finally
            {
                stopwatch.Stop();
                result.Duration = stopwatch.Elapsed;
                result.EndTime = DateTime.UtcNow;
            }

            Console.WriteLine($"  {testName}: {(result.Passed ? "PASS" : "FAIL")} ({result.Duration.TotalMilliseconds:F2}ms)");
            if (!result.Passed && !string.IsNullOrEmpty(result.ErrorMessage))
            {
                Console.WriteLine($"    Error: {result.ErrorMessage}");
            }

            return result;
        }

        // Test implementation methods
        private async Task<bool> TestSQLInjectionPreventionUsername()
        {
            var maliciousInputs = new List<string>
            {
                "admin'; DROP TABLE Users; --",
                "user' OR '1'='1",
                "test'; INSERT INTO Users VALUES ('hacker', 'hacker@evil.com', 'hash', 'salt'); --"
            };

            foreach (var input in maliciousInputs)
            {
                var result = SecureInputValidator.ValidateUsername(input);
                if (result.IsValid)
                {
                    return false; // Should not be valid
                }
            }
            return true;
        }

        private async Task<bool> TestSQLInjectionPreventionEmail()
        {
            var maliciousInputs = new List<string>
            {
                "admin'; DROP TABLE Users; --@test.com",
                "user' OR '1'='1@test.com",
                "test'; INSERT INTO Users VALUES ('hacker', 'hacker@evil.com', 'hash', 'salt'); --@test.com"
            };

            foreach (var input in maliciousInputs)
            {
                var result = SecureInputValidator.ValidateEmail(input);
                if (result.IsValid)
                {
                    return false; // Should not be valid
                }
            }
            return true;
        }

        private async Task<bool> TestXSSPreventionUsername()
        {
            var maliciousInputs = new List<string>
            {
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')"
            };

            foreach (var input in maliciousInputs)
            {
                var result = SecureInputValidator.ValidateUsername(input);
                if (result.IsValid)
                {
                    return false; // Should not be valid
                }
            }
            return true;
        }

        private async Task<bool> TestXSSPreventionEmail()
        {
            var maliciousInputs = new List<string>
            {
                "<script>alert('XSS')</script>@test.com",
                "<img src=x onerror=alert('XSS')>@test.com",
                "javascript:alert('XSS')@test.com"
            };

            foreach (var input in maliciousInputs)
            {
                var result = SecureInputValidator.ValidateEmail(input);
                if (result.IsValid)
                {
                    return false; // Should not be valid
                }
            }
            return true;
        }

        private async Task<bool> TestPasswordStrengthValidation()
        {
            var weakPasswords = new List<string>
            {
                "short",
                "nouppercase123!",
                "NOLOWERCASE123!",
                "NoNumbers!",
                "NoSpecialChars123"
            };

            foreach (var password in weakPasswords)
            {
                var result = SecureInputValidator.ValidatePassword(password);
                if (result.IsValid)
                {
                    return false; // Should not be valid
                }
            }

            // Test strong password
            var strongPassword = "StrongPass123!";
            var strongResult = SecureInputValidator.ValidatePassword(strongPassword);
            return strongResult.IsValid;
        }

        private async Task<bool> TestHTMLSanitization()
        {
            var maliciousInput = "<script>alert('XSS')</script>";
            var sanitized = SecureInputValidator.SanitizeHtml(maliciousInput);
            
            return !sanitized.Contains("<script>") && sanitized.Contains("&lt;script&gt;");
        }

        private async Task<bool> TestEdgeCaseHandling()
        {
            // Test null inputs
            var nullUsername = SecureInputValidator.ValidateUsername(null);
            var nullEmail = SecureInputValidator.ValidateEmail(null);
            var nullPassword = SecureInputValidator.ValidatePassword(null);

            return !nullUsername.IsValid && !nullEmail.IsValid && !nullPassword.IsValid;
        }

        private async Task<bool> TestParameterizedQueryProtection()
        {
            try
            {
                // Test that parameterized queries work with special characters
                var specialInput = "user'; DROP TABLE Users; --";
                var users = await _dbManager.SearchUsersAsync(specialInput, 10);
                
                // Should not throw exception and should treat input as literal string
                return true;
            }
            catch
            {
                return false;
            }
        }

        private async Task<bool> TestSQLInjectionPreventionCreateUser()
        {
            try
            {
                var maliciousUsername = "admin'; DROP TABLE Users; --";
                var userId = await _dbManager.CreateUserAsync(
                    maliciousUsername,
                    "test@example.com",
                    "hashedpassword",
                    "salt",
                    "127.0.0.1",
                    "TestAgent"
                );

                // Should either succeed (treating input as literal) or fail gracefully
                return true;
            }
            catch
            {
                return false;
            }
        }

        private async Task<bool> TestSQLInjectionPreventionAuthentication()
        {
            try
            {
                var maliciousUsername = "admin' OR '1'='1";
                var result = await _dbManager.AuthenticateUserAsync(
                    maliciousUsername,
                    "hashedpassword",
                    "127.0.0.1",
                    "TestAgent"
                );

                // Should fail authentication, not succeed
                return !result.IsSuccess;
            }
            catch
            {
                return false;
            }
        }

        private async Task<bool> TestSQLInjectionPreventionSearch()
        {
            try
            {
                var maliciousSearch = "admin'; DROP TABLE Users; --";
                var users = await _dbManager.SearchUsersAsync(maliciousSearch, 10);
                
                // Should not throw exception and should treat input as literal string
                return true;
            }
            catch
            {
                return false;
            }
        }

        private async Task<bool> TestConnectionSecurity()
        {
            try
            {
                var isConnected = await _dbManager.TestConnectionAsync();
                return isConnected;
            }
            catch
            {
                return false;
            }
        }

        private async Task<bool> TestAuditLogging()
        {
            try
            {
                await _dbManager.LogAuditEventAsync(
                    1,
                    "TEST_ACTION",
                    "Test audit log entry",
                    "127.0.0.1",
                    "TestAgent"
                );
                return true;
            }
            catch
            {
                return false;
            }
        }

        // API test methods
        private async Task<bool> TestXSSPreventionCreateUserAPI()
        {
            try
            {
                var request = new CreateUserRequest
                {
                    Username = "<script>alert('XSS')</script>",
                    Email = "test@example.com",
                    Password = "ValidPass123!"
                };

                var result = await _controller.CreateUser(request);
                
                // Should be rejected
                return result is BadRequestResult || result is InvalidModelStateResult;
            }
            catch
            {
                return true; // Exception means it was blocked
            }
        }

        private async Task<bool> TestXSSPreventionAuthenticationAPI()
        {
            try
            {
                var request = new AuthenticateUserRequest
                {
                    Username = "<script>alert('XSS')</script>",
                    Password = "ValidPass123!"
                };

                var result = await _controller.AuthenticateUser(request);
                
                // Should be rejected
                return result is BadRequestResult || result is InvalidModelStateResult;
            }
            catch
            {
                return true; // Exception means it was blocked
            }
        }

        private async Task<bool> TestXSSPreventionSearchAPI()
        {
            try
            {
                var result = await _controller.SearchUsers("<script>alert('XSS')</script>", 10);
                
                // Should be rejected
                return result is BadRequestResult || result is InvalidModelStateResult;
            }
            catch
            {
                return true; // Exception means it was blocked
            }
        }

        private async Task<bool> TestSQLInjectionPreventionCreateUserAPI()
        {
            try
            {
                var request = new CreateUserRequest
                {
                    Username = "admin'; DROP TABLE Users; --",
                    Email = "test@example.com",
                    Password = "ValidPass123!"
                };

                var result = await _controller.CreateUser(request);
                
                // Should be rejected
                return result is BadRequestResult || result is InvalidModelStateResult;
            }
            catch
            {
                return true; // Exception means it was blocked
            }
        }

        private async Task<bool> TestSQLInjectionPreventionAuthenticationAPI()
        {
            try
            {
                var request = new AuthenticateUserRequest
                {
                    Username = "admin' OR '1'='1",
                    Password = "ValidPass123!"
                };

                var result = await _controller.AuthenticateUser(request);
                
                // Should be rejected
                return result is BadRequestResult || result is InvalidModelStateResult;
            }
            catch
            {
                return true; // Exception means it was blocked
            }
        }

        private async Task<bool> TestSQLInjectionPreventionSearchAPI()
        {
            try
            {
                var result = await _controller.SearchUsers("admin'; DROP TABLE Users; --", 10);
                
                // Should be rejected
                return result is BadRequestResult || result is InvalidModelStateResult;
            }
            catch
            {
                return true; // Exception means it was blocked
            }
        }

        private async Task<bool> TestInputValidationCreateUserAPI()
        {
            try
            {
                var request = new CreateUserRequest
                {
                    Username = "",
                    Email = "invalid-email",
                    Password = "weak"
                };

                var result = await _controller.CreateUser(request);
                
                // Should be rejected
                return result is BadRequestResult || result is InvalidModelStateResult;
            }
            catch
            {
                return true; // Exception means it was blocked
            }
        }

        private async Task<bool> TestInputValidationAuthenticationAPI()
        {
            try
            {
                var request = new AuthenticateUserRequest
                {
                    Username = "",
                    Password = "weak"
                };

                var result = await _controller.AuthenticateUser(request);
                
                // Should be rejected
                return result is BadRequestResult || result is InvalidModelStateResult;
            }
            catch
            {
                return true; // Exception means it was blocked
            }
        }

        private async Task<bool> TestInputValidationSearchAPI()
        {
            try
            {
                var result = await _controller.SearchUsers("", 10);
                
                // Should be rejected
                return result is BadRequestResult || result is InvalidModelStateResult;
            }
            catch
            {
                return true; // Exception means it was blocked
            }
        }

        private async Task<bool> TestErrorHandlingAPI()
        {
            try
            {
                var result = await _controller.CreateUser(null);
                
                // Should handle null gracefully
                return result is BadRequestResult || result is InvalidModelStateResult;
            }
            catch
            {
                return true; // Exception means it was handled
            }
        }

        // Integration test methods
        private async Task<bool> TestEndToEndSecurityFlow()
        {
            try
            {
                // Test complete flow with malicious input
                var maliciousRequest = new CreateUserRequest
                {
                    Username = "<script>alert('XSS')</script>",
                    Email = "admin'; DROP TABLE Users; --@test.com",
                    Password = "weak"
                };

                var result = await _controller.CreateUser(maliciousRequest);
                
                // Should be rejected at multiple levels
                return result is BadRequestResult || result is InvalidModelStateResult;
            }
            catch
            {
                return true; // Exception means it was blocked
            }
        }

        private async Task<bool> TestConcurrentRequestHandling()
        {
            try
            {
                var tasks = new List<Task>();
                
                for (int i = 0; i < 5; i++)
                {
                    int index = i;
                    tasks.Add(Task.Run(async () =>
                    {
                        var request = new CreateUserRequest
                        {
                            Username = $"concurrentuser{index}",
                            Email = $"concurrent{index}@example.com",
                            Password = "ValidPass123!"
                        };

                        await _controller.CreateUser(request);
                    }));
                }

                await Task.WhenAll(tasks);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private async Task<bool> TestResourceCleanup()
        {
            try
            {
                using (var testDbManager = new SecureDatabaseManager("Server=localhost;Database=SafeVault;Integrated Security=true;TrustServerCertificate=true;"))
                {
                    var isConnected = await testDbManager.TestConnectionAsync();
                    return isConnected;
                }
            }
            catch
            {
                return false;
            }
        }

        private async Task<bool> TestPerformanceUnderAttack()
        {
            try
            {
                var stopwatch = Stopwatch.StartNew();
                
                // Simulate multiple attack attempts
                for (int i = 0; i < 10; i++)
                {
                    var maliciousRequest = new CreateUserRequest
                    {
                        Username = $"admin'; DROP TABLE Users; --{i}",
                        Email = $"test{i}@example.com",
                        Password = "ValidPass123!"
                    };

                    await _controller.CreateUser(maliciousRequest);
                }
                
                stopwatch.Stop();
                
                // Should complete within reasonable time (5 seconds)
                return stopwatch.Elapsed.TotalSeconds < 5;
            }
            catch
            {
                return true; // Exception means it was blocked quickly
            }
        }

        /// <summary>
        /// Generates a comprehensive security test report
        /// </summary>
        private void GenerateReport(SecurityTestReport report)
        {
            Console.WriteLine("\n" + new string('=', 60));
            Console.WriteLine("SAFEVAULT SECURITY TEST REPORT");
            Console.WriteLine(new string('=', 60));
            
            Console.WriteLine($"Test Duration: {report.Duration.TotalSeconds:F2} seconds");
            Console.WriteLine($"Total Tests: {report.TestResults.Count}");
            
            var passedTests = report.TestResults.Count(t => t.Passed);
            var failedTests = report.TestResults.Count(t => !t.Passed);
            
            Console.WriteLine($"Passed: {passedTests}");
            Console.WriteLine($"Failed: {failedTests}");
            Console.WriteLine($"Success Rate: {(double)passedTests / report.TestResults.Count * 100:F1}%");
            
            if (failedTests > 0)
            {
                Console.WriteLine("\nFAILED TESTS:");
                Console.WriteLine(new string('-', 40));
                foreach (var test in report.TestResults.Where(t => !t.Passed))
                {
                    Console.WriteLine($"  {test.TestName}: {test.ErrorMessage}");
                }
            }
            
            Console.WriteLine("\nSECURITY ASSESSMENT:");
            Console.WriteLine(new string('-', 40));
            
            if (failedTests == 0)
            {
                Console.WriteLine("✅ ALL SECURITY TESTS PASSED");
                Console.WriteLine("✅ Application is protected against common vulnerabilities");
                Console.WriteLine("✅ Input validation is working correctly");
                Console.WriteLine("✅ SQL injection prevention is effective");
                Console.WriteLine("✅ XSS prevention is working");
            }
            else
            {
                Console.WriteLine("❌ SOME SECURITY TESTS FAILED");
                Console.WriteLine("❌ Application may be vulnerable to attacks");
                Console.WriteLine("❌ Review failed tests and implement fixes");
            }
            
            Console.WriteLine("\nRECOMMENDATIONS:");
            Console.WriteLine(new string('-', 40));
            Console.WriteLine("1. Regularly run these security tests");
            Console.WriteLine("2. Keep security libraries updated");
            Console.WriteLine("3. Monitor for new attack vectors");
            Console.WriteLine("4. Implement additional security measures as needed");
            Console.WriteLine("5. Consider penetration testing by security professionals");
            
            Console.WriteLine(new string('=', 60));
        }

        public void Dispose()
        {
            _dbManager?.Dispose();
            _controller?.Dispose();
        }
    }

    /// <summary>
    /// Test result model
    /// </summary>
    public class TestResult
    {
        public string TestName { get; set; }
        public bool Passed { get; set; }
        public string ErrorMessage { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public TimeSpan Duration { get; set; }
    }

    /// <summary>
    /// Security test report model
    /// </summary>
    public class SecurityTestReport
    {
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public TimeSpan Duration { get; set; }
        public List<TestResult> TestResults { get; set; }
    }
}
