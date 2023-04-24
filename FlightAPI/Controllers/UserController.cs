using FlightAPI.Models;
using FlightAPI.Services.UserService;
using FlightAPI.Services.UserService.DTO;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace FlightAPI.Controllers
{
    [Route("api/user")]

    //localhost:3000/api/User/1

    [ApiController]
    public class UserController : ControllerBase
    {
        public static User user = new User();
        private readonly IConfiguration _configuration;
        // goi service
        private readonly IUserService _userService;
        public UserController(IConfiguration configuration, IUserService userService)
        {
            _configuration = configuration;
            _userService = userService;
        }

        [HttpGet, Authorize]
        public ActionResult<string> GetMe()
        {
            var userName = _userService;
            return Ok(userName);
        }

        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserRegisterDTO request)
        {
            var result = await _userService.Register(request);

            if (result == null) 
                return BadRequest("Register failed !");

            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);

            user.Email = request.Email;
            user.Username = request.UserName;
            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;

            return Ok(user);
        }

        [HttpPost("login")]
        public async Task<ActionResult<User>> Login(UserLoginDTO request)
        {
            var result = await _userService.Login(request);

            if (result == null)
                return BadRequest("Login failed !");

            if (user.Email != request.Email)
            {
                return BadRequest("User not found.");
            }

            if (!VerifyPasswordHash(request.Password, user.PasswordHash, user.PasswordSalt))
            {
                return BadRequest("Wrong password.");
            }

            string token = CreateToken(user);

            var refreshToken = GenerateRefreshToken();
            SetRefreshToken(refreshToken);

            return Ok(token);
        }

        [HttpPost("refresh-token"), Authorize(Roles = "Admin")]
        public async Task<ActionResult<string>> RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];

            if (!user.RefreshToken.Equals(refreshToken))
            {
                return Unauthorized("Invalid Refresh Token.");
            }
            else if (user.TokenExpires < DateTime.Now)
            {
                return Unauthorized("Token expired.");
            }

            string token = CreateToken(user);
            var newRefreshToken = GenerateRefreshToken();
            SetRefreshToken(newRefreshToken);

            return Ok(token);
        }

        private RefreshToken GenerateRefreshToken()
        {
            var refreshToken = new RefreshToken
            {
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                Expires = DateTime.Now.AddDays(7),
                Created = DateTime.Now
            };

            return refreshToken;
        }

        private void SetRefreshToken(RefreshToken newRefreshToken)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = newRefreshToken.Expires
            };
            Response.Cookies.Append("refreshToken", newRefreshToken.Token, cookieOptions);

            user.RefreshToken = newRefreshToken.Token;
            user.TokenCreated = newRefreshToken.Created;
            user.TokenExpires = newRefreshToken.Expires;
        }

        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Role, "Admin")
            };

            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(
                _configuration.GetSection("AppSettings:Token").Value));

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
            using (var hmac = new HMACSHA512(passwordSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(passwordHash);
            }
        }

        [HttpPost("verify-email")]
        public async Task<ActionResult<User>> VerifyEmail(string token)
        {
            var result = await _userService.VerifyEmail(token);

            if (result == null)
                return BadRequest("Email verification failed !");

            return Ok("Email sucessfully verified !");
        }

        [HttpPost("forgot-password")]
        public async Task<ActionResult<User>> ForgotPassword(string email)
        {
            var result = await _userService.ForgotPassword(email);

            if (result == null)
                return BadRequest("Can't find your email address.");

            return Ok("Now, you can change the password.");
        }

        [HttpPost("reset-password")]
        public async Task<ActionResult<User>> ResetPassword(ResetPasswordDTO request)
        {
            var result = await _userService.ResetPassword(request);

            if (result == null)
                return BadRequest("Reset password failed !");

            return Ok("Reset password sucessfully !");
        }

        [HttpGet("get-all"), Authorize(Roles = "Admin")]
        public async Task<ActionResult<List<User>>> GetAllUser()
        {
            // Trả về toàn bộ dữ liệu || OK là status code 200
            return await _userService.GetAllUser();
        }

        [HttpGet("get-by-id/{id}")]
        public async Task<ActionResult<User>> GetUserProfile(int id)
        {
            // Tìm User bằng id
            var result = await _userService.GetUserProfile(id);
            if (result is null)
                return NotFound("user not found");

            return Ok(result);
        }

        [HttpPost("add"), Authorize(Roles = "Admin")]
        public async Task<ActionResult<List<User>>> AddUser(User user)
        {
            // dữ liệu mẫu đem Add thêm model user vào
            var result = await _userService.AddUser(user);
            if (result is null)
                return NotFound("user not found");

            return Ok(result);
        }

        [HttpPut("update/{id}")]
        public async Task<ActionResult<List<User>>> UpdateUser(int id, User user)
        {
            // tìm user
            var result = await _userService.UpdateUser(id, user);
            if (result is null)
                return NotFound("user not found");

            return Ok(result);
        }

        [HttpDelete("delete/{id}"), Authorize(Roles = "Admin")]
        public async Task<ActionResult<List<User>>> DeleteUser(int id)
        {

            var result = await _userService.DeleteUser(id);
            if (result is null)
                return NotFound("user not found");

            return NoContent();
        }
    }
}
