using AuthenticationInAspnetCore.Data;
using AuthenticationInAspnetCore.Entities;
using AuthenticationInAspnetCore.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AuthenticationInAspnetCore.Services
{
    public class AuthService : IAuthService
    {
        private readonly ApplicationDbContext _db;
        private readonly IConfiguration _configuration;

        public AuthService(ApplicationDbContext db, IConfiguration configuration)
        {
            _db = db;
            _configuration = configuration;
        }

        public async Task<User?> RegisterAsync(UserDto request)
        {
            var newuser = await _db.Users.AnyAsync(u => u.Username == request.Username);
            if (newuser)
            {
                return null;
            }
            var user = new User();
            user.Username = request.Username;
            user.PasswordHash = new PasswordHasher<User>().HashPassword(user, request.Password);
            await _db.Users.AddAsync(user);
            await _db.SaveChangesAsync();
            return user;
        }


        public async Task<string?> Login(UserDto request)
        {
            var user = await _db.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
            if (user is null)
            {
                return null;
            }
            var passwordHasher = new PasswordHasher<User>();
            var result = passwordHasher.VerifyHashedPassword(user, user.PasswordHash, request.Password);
            if (result == PasswordVerificationResult.Failed)
            {
                return null;
            }
            string Token = CreateToken(request);
            return Token;
        }

        private string CreateToken(UserDto user)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username),
                // Add additional claims as needed
            };
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.GetValue<string>("AppSetting:Token")!));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);
            var tokenDescriptor = new JwtSecurityToken(
                issuer: _configuration.GetValue<string>("AppSetting:issuer"),
                audience: _configuration.GetValue<string>("AppSetting:audience"),
                claims: claims,
                expires: DateTime.UtcNow.AddDays(1),
                signingCredentials: creds
            );
            return new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
        }

    }
}
