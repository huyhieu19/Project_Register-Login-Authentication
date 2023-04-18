using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using ProjectLoginAuth.Services.UserService;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace ProjectLoginAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User user = new User();

        private readonly IConfiguration _configuration;
        private readonly IUserService _userService;

        public AuthController(IConfiguration configuration, IUserService userService)
        {
            _configuration = configuration;
            _userService = userService;
        }
        [HttpGet, Authorize]
        public ActionResult<object> GetMe()
        {
            var userName = _userService.GetMyName();
            return Ok(userName);
        }


        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDto request)
        {
            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);
            user.UserName = request.UserName;
            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;
            return Ok(user);
        }
        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(UserDto request)
        {
            if(request.UserName != user.UserName)
            {
                return BadRequest("User not found");
            }
            if(!VerifyPasswordHash(request.Password, user.PasswordHash, user.PasswordSalt))
            {
                return BadRequest("Wrong password");
            }
            string token = CreateToken(user);

            var refreshToken = GenerateRefeshToken();
            SetRefreshToken(refreshToken);

            return Ok(token);
        }
        [HttpPost("refresh-token")]
        public async Task<ActionResult<string>> RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];
            if(!user.RefreshToken.Equals(refreshToken))
            {
                return Unauthorized("Invalid refresh token;");
            }else if(user.TokenExpires < DateTime.Now)
            {
                return Unauthorized("token expired.");
            }
            string token = CreateToken(user);
            var newRefreshToken = GenerateRefeshToken();
            SetRefreshToken(newRefreshToken);
            return Ok(token);
        }


        private RefreshToken GenerateRefeshToken()
        {
            var refreshToken = new RefreshToken()
            {
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                Exprires = DateTime.Now.AddSeconds(15),
                Created = DateTime.Now
           
            };
            return refreshToken;
        }

        private void SetRefreshToken(RefreshToken newRefreshToken)
        {
            var cookieOptions = new CookieOptions()
            {
                HttpOnly = true,
                Expires = newRefreshToken.Exprires,
            };
            Response.Cookies.Append("refreshToken", newRefreshToken.Token, cookieOptions);

            user.RefreshToken = newRefreshToken.Token;
            user.TokenExpires = newRefreshToken.Exprires;
            user.TokenCreated = newRefreshToken.Created;
        }

        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Role, "Admin")
            };

            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(_configuration.GetSection("AppSettings:Token").Value));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: creds);
            var jwt = new JwtSecurityTokenHandler().WriteToken(token);
            return jwt;
        }

        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt) 
        { 
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using(var hmac = new HMACSHA512(user.PasswordSalt))
            {
                var computeHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computeHash.SequenceEqual(passwordHash);
            }
        }
    }
}
