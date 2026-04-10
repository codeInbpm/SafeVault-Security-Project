using System.Linq;

namespace SafeVault.Helpers;

public static class ValidationHelpers
{
    public static bool IsValidInput(string input, string allowedSpecialCharacters = "")
    {
        if (string.IsNullOrEmpty(input))
            return false;

        var validCharacters = allowedSpecialCharacters.ToHashSet();
        return input.All(c => char.IsLetterOrDigit(c) || validCharacters.Contains(c));
    }

    public static bool IsValidXSSInput(string input)
    {
        if (string.IsNullOrEmpty(input))
            return true;

        string lowered = input.ToLower();
        if (lowered.Contains("<script") || lowered.Contains("<iframe"))
            return false;

        return true;
    }

    public static void TestXssInput()
    {
        string maliciousInput = "<script>alert('XSS');</script>";
        bool isValid = IsValidXSSInput(maliciousInput);
        Console.WriteLine(isValid ? "XSS Test Failed" : "XSS Test Passed");
    }
}