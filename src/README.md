# SafeVault Security Project Submission

## 1. Identified Vulnerabilities
- **SQL Injection**: Found in the database query logic where user input was directly concatenated.
- **XSS (Cross-Site Scripting)**: Found in the Admin dashboard where logs were displayed without encoding.
- **Broken Access Control**: Sensitive routes were accessible without proper role verification.

## 2. Fixes Applied
- Implemented **Parameterized Queries** via Entity Framework Core to block SQL injection.
- Applied **HTML Encoding** using `HtmlEncoder` to mitigate XSS risks.
- Configured **ASP.NET Identity with RBAC** to restrict sensitive actions to authorized "Admin" users.

## 3. Microsoft Copilot Assistance
Microsoft Copilot helped by:
- Generating secure boilerplate for Identity configuration.
- Suggesting `FromSqlInterpolated` as a safe alternative to raw SQL.
- Identifying missing `[Authorize]` attributes in controllers.
- Writing the XUnit security test cases.