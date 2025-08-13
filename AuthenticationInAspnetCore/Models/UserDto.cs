namespace AuthenticationInAspnetCore.Models
{
    public class UserDto
    {
        public string Username { get; set; }
        public string Password { get; set; }
         public List<string> Roles { get; set; }
    }
}
