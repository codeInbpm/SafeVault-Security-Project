using System.Data.SqlClient;

namespace SafeVault.Helpers
{
    public class AuthService
    {
        public bool LoginUser(string username, string password)
        {
            string allowedSpecialCharacters = "!@#$%^&*?";

            if (!ValidationHelpers.IsValidInput(username) ||
                !ValidationHelpers.IsValidInput(password, allowedSpecialCharacters))
                return false;

            string query = "SELECT COUNT(1) FROM Users WHERE Username = @Username AND Password = @Password";
            using (var connection = new SqlConnection("Server=localhost;Database=Coursera;Trusted_Connection=True;"))
            using (var command = new SqlCommand(query, connection))
            {
                command.Parameters.AddWithValue("@Username", username);
                command.Parameters.AddWithValue("@Password", password);

                connection.Open();
                int count = (int)command.ExecuteScalar();
                return count > 0;
            }
        }

        public User GetUserByUsername(string username)
        {
            using (var connection = new SqlConnection("Server=localhost;Database=Coursera;Trusted_Connection=True;"))
            using (var command = new SqlCommand("SELECT Username, Email FROM Users WHERE Username = @Username", connection))
            {
                command.Parameters.AddWithValue("@Username", username);
                connection.Open();
                using (var reader = command.ExecuteReader())
                {
                    if (reader.Read())
                    {
                        return new User
                        {
                            Username = reader.GetString(reader.GetOrdinal("Username")),
                            Email = reader.GetString(reader.GetOrdinal("Email"))
                        };
                    }
                    return null;
                }
            }
        }

        // Example User class
        public class User
        {
            public string Username { get; set; }
            public string Email { get; set; }
        }


    }
}