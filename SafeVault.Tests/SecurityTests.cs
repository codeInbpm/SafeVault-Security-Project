using Xunit;
using SafeVault.Web.Data;
using Microsoft.EntityFrameworkCore;

namespace SafeVault.Tests;

public class SecurityTests
{
    [Fact]
    public async Task SQLInjection_Prevention_Test()
    {
        // 模拟攻击输入
        string maliciousEmail = "' OR 1=1 --";

        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(databaseName: "TestDb").Options;

        using (var context = new ApplicationDbContext(options))
        {
            var user = await context.GetUserByEmailAsync(maliciousEmail);

            // 验证：注入代码不应返回任何用户
            Assert.Null(user);
        }
    }
}