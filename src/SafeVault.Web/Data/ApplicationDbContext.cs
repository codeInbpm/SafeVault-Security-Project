using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace SafeVault.Web.Data;

public class ApplicationDbContext : IdentityDbContext
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options) { }

    // 示例：使用参数化查询预防 SQL 注入
    public async Task<UserAccount> GetUserByEmailAsync(string email)
    {
        // Microsoft Copilot 建议：永远不要使用字符串拼接存储过程
        // FromSqlInterpolated 会自动将 {email} 处理为参数，防止注入
        return await this.Set<UserAccount>()
            .FromSqlInterpolated($"SELECT * FROM Users WHERE Email = {email}")
            .FirstOrDefaultAsync();
    }
}

public class UserAccount { public int Id { get; set; } public string Email { get; set; } }