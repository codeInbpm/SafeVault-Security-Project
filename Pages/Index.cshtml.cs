using Microsoft.AspNetCore.Mvc.RazorPages;
using SafeVault.Helpers;
using Microsoft.AspNetCore.Mvc;


namespace SafeVault.Pages;

public class IndexModel : PageModel
{
    [BindProperty]
    public string Username { get; set; }

    [BindProperty]
    public string Email { get; set; }


    public void OnGet()
    {

    }

    public IActionResult OnPost()
    {
          if (!ValidationHelpers.IsValidInput(Username, "@#$"))
        {
            ModelState.AddModelError("Username", "Invalid username.");
        }
        if (!ValidationHelpers.IsValidInput(Email, "@#$"))
        {
            ModelState.AddModelError("Email", "Invalid email.");
        }

        if (!ModelState.IsValid)
        {
            return Page();
        }

        // Safe to process input here
        return RedirectToPage("Success");
    }
}
