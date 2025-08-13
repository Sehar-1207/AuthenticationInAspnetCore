using AuthenticationInAspnetCore.Entities;
using AuthenticationInAspnetCore.Models;
using AuthenticationInAspnetCore.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationInAspnetCore.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly IAuthService _service;

        public AuthenticationController(IAuthService service)
        {
            _service = service;
        }

        [HttpPost("register")]
        public async Task<ActionResult<User?>> Register([FromBody] UserDto request)
        {
            var user = await _service.RegisterAsync(request);
            if (user is null)
            {
                return BadRequest(new { Message = "User already exists" });
            }
            return Ok(new { Message = "User registered successfully", User = request });
        }

        [HttpPost("login")]
        public async Task<ActionResult<TokenResponseDto>> Login(UserDto request)
        {
            var token = await _service.Login(request);
            if (token is null)
            {
                return Unauthorized(new { Message = "Invalid username or password" });
            }
            return Ok(token);
        }

        [HttpPost("refreshtoken")]
        public async Task<ActionResult<TokenResponseDto>> refreshToken(RefreshTokenRequestDto request)
        {
            var token = await _service.RefreshTokenAsync(request);
            if(token is null)
            {
                return Unauthorized(new { Message = "Invalid token. or token expired" });
            }

            return Ok(token);
        }

        [HttpPost("test")]
        [Authorize]
        public IActionResult Test()
        {
            return Ok(new { Message = "You are authenticated!" });
        }
    }
}
