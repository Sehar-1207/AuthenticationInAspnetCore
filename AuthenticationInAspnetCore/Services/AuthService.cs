using AuthenticationInAspnetCore.Data;
using AuthenticationInAspnetCore.Entities;
using AuthenticationInAspnetCore.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
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
            var exists = await _db.Users.AnyAsync(u => u.Username == request.Username);
            if (exists) return null;

            var user = new User
            {
                Username = request.Username,
                PasswordHash = new PasswordHasher<User>().HashPassword(null!, request.Password),
                Roles = string.Join(",", request.Roles ?? new List<string>()),
                RefreshToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
                RefreshTokenExpiry = DateTime.UtcNow.AddDays(1)
            };

            await _db.Users.AddAsync(user);
            await _db.SaveChangesAsync();
            return user;
        }


        //Only when returning token 
        //public async Task<string?> Login(UserDto request)
        //{
        //    var user = await _db.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
        //    if (user is null)
        //    {
        //        return null;
        //    }
        //    var passwordHasher = new PasswordHasher<User>();
        //    var result = passwordHasher.VerifyHashedPassword(user, user.PasswordHash, request.Password);
        //    if (result == PasswordVerificationResult.Failed)
        //    {
        //        return null;
        //    }
        //    string Token = CreateToken(user);
        //    return Token;
        //}

        public async Task<TokenResponseDto?> Login(UserDto request)
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
            var token = new TokenResponseDto
            {
                AccessToken = CreateToken(user),
                RefreshToken = await GenerateFreshTokenAsync(user)
            };
            return token;
        }


        private async Task<string?> GenerateFreshTokenAsync(User user)
        {
            var num = new byte[32];
            using var generator = RandomNumberGenerator.Create();
            generator.GetBytes(num);
            var refreshToken = Convert.ToBase64String(num);
            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiry = DateTime.UtcNow.AddDays(1);
            await _db.SaveChangesAsync();
            return refreshToken;
        }
        //private string CreateToken(User user)
        //{
        //    var claims = new List<Claim>
        //    {
        //        new Claim(ClaimTypes.Name, user.Username),
        //        new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
        //        new Claim(ClaimTypes.Role, user.Roles),
        //        // Add additional claims as needed
        //    };
        //    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.GetValue<string>("AppSetting:Token")!));
        //    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);
        //    var tokenDescriptor = new JwtSecurityToken(
        //        issuer: _configuration.GetValue<string>("AppSetting:issuer"),
        //        audience: _configuration.GetValue<string>("AppSetting:audience"),
        //        claims: claims,
        //        expires: DateTime.UtcNow.AddDays(1),
        //        signingCredentials: creds
        //    );
        //    return new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
        //}
        private string CreateToken(User user)
        {
            var claims = new List<Claim>
    {
        new Claim(ClaimTypes.Name, user.Username),
        new Claim(ClaimTypes.NameIdentifier, user.Id.ToString())
    };

            // Split roles and add each one separately
            var roleList = (user.Roles ?? "")
                .Split(",", StringSplitOptions.RemoveEmptyEntries)
                .Select(r => r.Trim());

            foreach (var role in roleList)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            var key = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(_configuration.GetValue<string>("AppSetting:Token")!)
            );
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

        public async Task<TokenResponseDto?> RefreshTokenAsync(RefreshTokenRequestDto request)
        {
            var user = await _db.Users.FindAsync(request.userId);
            if (user is null || user.RefreshToken != request.RefreshToken || user.RefreshTokenExpiry < DateTime.UtcNow)
            {
                return null;
            }
            var token = new TokenResponseDto
            {
                AccessToken = CreateToken(user),
                RefreshToken = await GenerateFreshTokenAsync(user)
            };
            return token;
        }

    }
}
