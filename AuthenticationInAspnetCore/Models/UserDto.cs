namespace AuthenticationInAspnetCore.Models
{
    public class UserDto
    {
        public string Username { get; set; }
        public string Password { get; set; }
        // Additional properties can be added as needed
        // For example, you might want to include roles or claims
        // public List<string> Roles { get; set; }
        // public List<Claim> Claims { get; set; }
    }
}
