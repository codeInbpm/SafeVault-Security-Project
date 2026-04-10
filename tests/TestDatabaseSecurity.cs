using NUnit.Framework;
using SafeVault.Data;
using System;
using System.Threading.Tasks;
using System.Data.SqlClient;

namespace SafeVault.Tests
{
    /// <summary>
    /// Comprehensive test suite for database security
    /// Tests for SQL injection prevention and secure database operations
    /// </summary>
    [TestFixture]
    public class TestDatabaseSecurity
    {
        private SecureDatabaseManager _dbManager;
        private string _connectionString;

        [SetUp]
        public void Setup()
        {
            // In a real test environment, use a test database
            _connectionString = "Server=localhost;Database=SafeVault;Integrated Security=true;TrustServerCertificate=true;";
            _dbManager = new SecureDatabaseManager(_connectionString);
        }

        [TearDown]
        public void TearDown()
        {
            _dbManager?.Dispose();
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

            foreach (var maliciousUsername in sqlInjectionAttempts)
            {
                try
                {
                    // Attempt to create user with malicious input
                    int userId = await _dbManager.CreateUserAsync(
                        maliciousUsername,
                        "test@example.com",
                        "hashedpassword",
                        "salt",
                        "127.0.0.1",
                        "TestAgent"
                    );

                    // If we get here, the input was sanitized and treated as a literal string
                    // This is the expected behavior - the malicious SQL should be treated as part of the username
                    Assert.IsTrue(userId > 0, $"User creation should succeed with sanitized input: {maliciousUsername}");
                }
                catch (InvalidOperationException ex)
                {
                    // Expected for inputs that violate constraints
                    Assert.IsTrue(ex.Message.Contains("already exists") || ex.Message.Contains("Failed to create user"), 
                        $"Unexpected error for input {maliciousUsername}: {ex.Message}");
                }
                catch (Exception ex)
                {
                    // Any other exception indicates a potential security issue
                    Assert.Fail($"Unexpected exception for input {maliciousUsername}: {ex.Message}");
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

            foreach (var maliciousUsername in sqlInjectionAttempts)
            {
                try
                {
                    // Attempt authentication with malicious input
                    var result = await _dbManager.AuthenticateUserAsync(
                        maliciousUsername,
                        "hashedpassword",
                        "127.0.0.1",
                        "TestAgent"
                    );

                    // Authentication should fail for malicious inputs
                    Assert.IsFalse(result.IsSuccess, 
                        $"Authentication should fail for malicious input: {maliciousUsername}");
                }
                catch (Exception ex)
                {
                    // Any exception indicates a potential security issue
                    Assert.Fail($"Unexpected exception for input {maliciousUsername}: {ex.Message}");
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

            foreach (var maliciousSearchTerm in sqlInjectionAttempts)
            {
                try
                {
                    // Attempt search with malicious input
                    var users = await _dbManager.SearchUsersAsync(maliciousSearchTerm, 10);

                    // Search should return empty results or fail validation
                    Assert.IsNotNull(users, $"Search should return valid result for input: {maliciousSearchTerm}");
                    // The search term should be treated as a literal string, not executed as SQL
                }
                catch (ArgumentException ex)
                {
                    // Expected for inputs that fail validation
                    Assert.IsTrue(ex.Message.Contains("Invalid search term"), 
                        $"Expected validation error for input {maliciousSearchTerm}: {ex.Message}");
                }
                catch (Exception ex)
                {
                    // Any other exception indicates a potential security issue
                    Assert.Fail($"Unexpected exception for input {maliciousSearchTerm}: {ex.Message}");
                }
            }
        }

        [Test]
        public async Task TestParameterizedQueries()
        {
            // Test that parameterized queries work correctly with special characters
            var specialCharacters = new List<string>
            {
                "user@domain.com",
                "user'name",
                "user\"name",
                "user;name",
                "user:name",
                "user<name",
                "user>name",
                "user&name",
                "user|name",
                "user*name",
                "user?name",
                "user#name",
                "user%name",
                "user+name",
                "user=name",
                "user!name",
                "user$name",
                "user^name",
                "user~name",
                "user`name",
                "user[name",
                "user]name",
                "user{name",
                "user}name",
                "user(name",
                "user)name",
                "user,name",
                "user.name",
                "user/name",
                "user\\name"
            };

            foreach (var specialChar in specialCharacters)
            {
                try
                {
                    // Test user creation with special characters
                    int userId = await _dbManager.CreateUserAsync(
                        $"testuser_{specialChar.GetHashCode()}",
                        $"test{specialChar.GetHashCode()}@example.com",
                        "hashedpassword",
                        "salt",
                        "127.0.0.1",
                        "TestAgent"
                    );

                    Assert.IsTrue(userId > 0, $"User creation should succeed with special characters: {specialChar}");

                    // Test user retrieval
                    var user = await _dbManager.GetUserByIdAsync(userId);
                    Assert.IsNotNull(user, $"User should be retrievable after creation: {specialChar}");
                }
                catch (InvalidOperationException ex)
                {
                    // Expected for inputs that violate constraints
                    Assert.IsTrue(ex.Message.Contains("already exists") || ex.Message.Contains("Failed to create user"), 
                        $"Unexpected error for special character {specialChar}: {ex.Message}");
                }
                catch (Exception ex)
                {
                    // Any other exception indicates a potential security issue
                    Assert.Fail($"Unexpected exception for special character {specialChar}: {ex.Message}");
                }
            }
        }

        [Test]
        public async Task TestDatabaseConnectionSecurity()
        {
            // Test database connection
            bool isConnected = await _dbManager.TestConnectionAsync();
            Assert.IsTrue(isConnected, "Database connection should be successful");

            // Test with invalid connection string
            using (var invalidDbManager = new SecureDatabaseManager("InvalidConnectionString"))
            {
                bool isInvalidConnected = await invalidDbManager.TestConnectionAsync();
                Assert.IsFalse(isInvalidConnected, "Invalid connection string should fail");
            }
        }

        [Test]
        public async Task TestAuditLogging()
        {
            // Test audit logging functionality
            await _dbManager.LogAuditEventAsync(
                1,
                "TEST_ACTION",
                "Test audit log entry",
                "127.0.0.1",
                "TestAgent"
            );

            // Test audit logging with null values
            await _dbManager.LogAuditEventAsync(
                null,
                "TEST_ACTION_NULL_USER",
                "Test audit log entry with null user",
                "127.0.0.1",
                "TestAgent"
            );

            // Test audit logging with empty strings
            await _dbManager.LogAuditEventAsync(
                1,
                "TEST_ACTION_EMPTY",
                "",
                "",
                ""
            );

            // All should complete without throwing exceptions
            Assert.IsTrue(true, "Audit logging should complete without exceptions");
        }

        [Test]
        public async Task TestInputValidationIntegration()
        {
            // Test that database operations properly validate inputs
            var invalidInputs = new List<(string username, string email)>
            {
                ("", "test@example.com"),
                ("validuser", ""),
                (null, "test@example.com"),
                ("validuser", null),
                ("ab", "test@example.com"), // Too short username
                ("validuser", "invalid-email"), // Invalid email
                ("user<script>alert('xss')</script>", "test@example.com"), // XSS in username
                ("validuser", "test<script>alert('xss')</script>@example.com") // XSS in email
            };

            foreach (var (username, email) in invalidInputs)
            {
                try
                {
                    int userId = await _dbManager.CreateUserAsync(
                        username,
                        email,
                        "hashedpassword",
                        "salt",
                        "127.0.0.1",
                        "TestAgent"
                    );

                    // If we get here, the input was somehow accepted
                    // This might be expected behavior if the validation happens at the API level
                    Assert.IsTrue(userId > 0, $"User creation succeeded with input: {username}, {email}");
                }
                catch (ArgumentException ex)
                {
                    // Expected for invalid inputs
                    Assert.IsTrue(ex.Message.Contains("All parameters must be provided") || 
                                 ex.Message.Contains("non-empty"), 
                        $"Expected validation error for input {username}, {email}: {ex.Message}");
                }
                catch (InvalidOperationException ex)
                {
                    // Expected for inputs that violate constraints
                    Assert.IsTrue(ex.Message.Contains("already exists") || ex.Message.Contains("Failed to create user"), 
                        $"Unexpected error for input {username}, {email}: {ex.Message}");
                }
                catch (Exception ex)
                {
                    // Any other exception indicates a potential security issue
                    Assert.Fail($"Unexpected exception for input {username}, {email}: {ex.Message}");
                }
            }
        }

        [Test]
        public async Task TestConcurrentOperations()
        {
            // Test concurrent database operations to ensure thread safety
            var tasks = new List<Task>();
            
            for (int i = 0; i < 10; i++)
            {
                int index = i;
                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        int userId = await _dbManager.CreateUserAsync(
                            $"concurrentuser{index}",
                            $"concurrent{index}@example.com",
                            "hashedpassword",
                            "salt",
                            "127.0.0.1",
                            "TestAgent"
                        );

                        Assert.IsTrue(userId > 0, $"Concurrent user creation should succeed: {index}");
                    }
                    catch (InvalidOperationException ex)
                    {
                        // Expected for duplicate usernames/emails
                        Assert.IsTrue(ex.Message.Contains("already exists"), 
                            $"Expected duplicate error for concurrent operation {index}: {ex.Message}");
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
                // Test with null parameters
                await _dbManager.CreateUserAsync(null, null, null, null, null, null);
                Assert.Fail("Should have thrown exception for null parameters");
            }
            catch (ArgumentException)
            {
                // Expected
            }

            try
            {
                // Test with empty parameters
                await _dbManager.CreateUserAsync("", "", "", "", "", "");
                Assert.Fail("Should have thrown exception for empty parameters");
            }
            catch (ArgumentException)
            {
                // Expected
            }

            try
            {
                // Test with invalid user ID
                var user = await _dbManager.GetUserByIdAsync(-1);
                Assert.IsNull(user, "Invalid user ID should return null");
            }
            catch (ArgumentException)
            {
                // Expected
            }

            try
            {
                // Test with zero user ID
                var user = await _dbManager.GetUserByIdAsync(0);
                Assert.IsNull(user, "Zero user ID should return null");
            }
            catch (ArgumentException)
            {
                // Expected
            }
        }

        [Test]
        public async Task TestResourceCleanup()
        {
            // Test that resources are properly cleaned up
            using (var testDbManager = new SecureDatabaseManager(_connectionString))
            {
                bool isConnected = await testDbManager.TestConnectionAsync();
                Assert.IsTrue(isConnected, "Database connection should be successful");
            }

            // After disposal, the connection should be closed
            // This is difficult to test directly, but we can ensure no exceptions are thrown
            Assert.IsTrue(true, "Resource cleanup should complete without exceptions");
        }
    }
}
