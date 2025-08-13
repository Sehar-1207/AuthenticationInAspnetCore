namespace AuthenticationInAspnetCore.Models
{
    public class RefreshTokenRequestDto
    {
        public Guid userId { get; set; }
        public string RefreshToken { get; set; }

    }
}
