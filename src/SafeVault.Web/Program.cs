using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SafeVault.Web.Data;

var builder = WebApplication.CreateBuilder(args);

// 1. 配置数据库
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseInMemoryDatabase("SafeVaultDb"));

// 2. 配置 Identity (认证)
builder.Services.AddDefaultIdentity<IdentityUser>(options => {
    options.SignIn.RequireConfirmedAccount = true;
    options.Password.RequiredLength = 12; // 安全增强
})
.AddRoles<IdentityRole>() // 启用 RBAC 角色支持
.AddEntityFrameworkStores<ApplicationDbContext>();

// 3. 配置授权策略
builder.Services.AddAuthorization(options => {
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.Run();