using AuthenticationInAspnetCore.Entities;
using AuthenticationInAspnetCore.Models;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationInAspnetCore.Services
{
    public interface IAuthService
    {
        Task<string?> Login(UserDto request);
        Task<User?> RegisterAsync(UserDto request);
    }
}