using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Text.Encodings.Web;

namespace SafeVault.Web.Controllers;

[Authorize(Roles = "Admin")] // 仅限 Admin 角色访问 (RBAC)
public class AdminController : Controller
{
    private readonly HtmlEncoder _htmlEncoder;

    public AdminController(HtmlEncoder htmlEncoder)
    {
        _htmlEncoder = htmlEncoder;
    }

    [HttpPost]
    public IActionResult UpdateVaultLogs(string userInput)
    {
        // 修复 XSS 漏洞：对用户输入进行 HTML 编码后再处理
        string safeInput = _htmlEncoder.Encode(userInput);

        ViewBag.Status = $"Logs updated with: {safeInput}";
        return View();
    }
}