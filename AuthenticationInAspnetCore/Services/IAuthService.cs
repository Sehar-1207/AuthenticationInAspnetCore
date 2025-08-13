using AuthenticationInAspnetCore.Entities;
using AuthenticationInAspnetCore.Models;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationInAspnetCore.Services
{
    public interface IAuthService
    {
        Task<TokenResponseDto?> Login(UserDto request);
        Task<TokenResponseDto?> RefreshTokenAsync(RefreshTokenRequestDto request);
        Task<User?> RegisterAsync(UserDto request);
    }
}