using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using AuthApi.Context;
using AuthApi.Helpers;
using AuthApi.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace AngularAuthApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly AppDbContext _appDbContext;
        public UserController(AppDbContext appDbContext)
        {
            _appDbContext = appDbContext;
        }

        [Authorize]
        [HttpGet]
        public async Task<IActionResult> GetAllUsers()
        {
            /// <summary>
            /// The appDbContext
            /// </summary>
            var userDetails = await _appDbContext.Users.ToListAsync();
            if (userDetails != null)
            {
                return Ok(userDetails);
            }
            else
            {
                return Unauthorized( new { Message = "ser is Unauthorized"});
            }
        }
        /// <summary>
        /// user authentication
        /// </summary>
        /// <param name="loginDto"></param>
        /// <returns></returns>
        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate([FromBody] loginDto loginDto)
        {
            if (loginDto == null)
                return BadRequest();
            var user = await _appDbContext.Users.FirstOrDefaultAsync(x => x.Username == loginDto.Username);
            if (user == null)
                return NotFound(new { Message = "User Not Found !" });
            if (!PasswordHasher.VerifyPassword(loginDto.Password, user.Password))
            {
                return BadRequest(new { Message = "Password is Incorrect !" });
            }
            if (loginDto.TokenExpiryTime == 0)
                return BadRequest(new { Message = "token expiry time is Null object" });
            var Token = CreateJwt(user, loginDto);
            var newAccessToken = Token;
            var newRefreshToken = CreateRefreshToken();
            user.RefreshToken = newRefreshToken;
            user.RefreshTokenExpiryTime = DateTime.Now.AddDays(1);
            await _appDbContext.SaveChangesAsync();
            if (Token == null)
            {
                return BadRequest(new
                {
                    Message = "Invalid Token"
                });
            }
            return Ok(new TokenApiDto()
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken
            });

        }
        /// <summary>
        /// refresh token
        /// </summary>
        /// <param name="tokenApiDto"></param>
        /// <returns></returns>
        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh(TokenApiDto tokenApiDto)
        {
            if (tokenApiDto is null)
                return BadRequest("Invalid Client Request");
            string accessToken = tokenApiDto.AccessToken;
            string refreshToken = tokenApiDto.RefreshToken;
            var principal = GetPrincipalFromExpiredToken(accessToken);
            var username = principal.Identity.Name;
            var user = await _appDbContext.Users.FirstOrDefaultAsync(u => u.Username == username);
            if (user is null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime <= DateTime.Now)
                return BadRequest("Invalid Request");
            var loginDto = new loginDto();
            var newAccessToken = CreateJwt(user, loginDto);
            if (newAccessToken is null)
                return BadRequest(new { Message = "token is null" });
            var newRefreshToken = CreateRefreshToken();
            user.RefreshToken = newRefreshToken;
            return Ok(new TokenApiDto()
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken
            });

        }
        /// <summary>
        /// user registeration
        /// </summary>
        /// <param name="userObj"></param>
        /// <returns></returns>
        [HttpPost("register")]
        public async Task<IActionResult> RegisterUser([FromBody] User userObj)
        {
            if (userObj == null)
                return BadRequest();
            //Check Email
            if (await CheckEmailExistAsync(userObj.Email))
                return BadRequest(new { Message = "Email is already exist!" });

            //Check Username
            if (await CheckUsernameExistAsync(userObj.Username))
                return BadRequest(new { Message = "Username is already exist!" });
            // Check Password Strength
            var pass = CheckPasswordStrength(userObj.Password);
            if (!string.IsNullOrEmpty(pass))
                return BadRequest(new { Message = pass.ToString() });

            userObj.Password = PasswordHasher.HashPassword(userObj.Password);
            userObj.Role = "User";
            await _appDbContext.Users.AddAsync(userObj);
            await _appDbContext.SaveChangesAsync();

            return Ok(new
            {
                Message = " User Registered Successfully !"
            });
        }
        /// <summary>
        /// username validation
        /// </summary>
        /// <param name="username"></param>
        /// <returns></returns>
        private async Task<bool> CheckUsernameExistAsync(string username)
        {
            return await _appDbContext.Users.AnyAsync(x => x.Username == username);

        }
        /// <summary>
        /// user email validation
        /// </summary>
        /// <param name="email"></param>
        /// <returns></returns>
        private async Task<bool> CheckEmailExistAsync(string email)
        {
            return await _appDbContext.Users.AnyAsync(x => x.Email == email);

        }
        /// <summary>
        /// uer password validation
        /// </summary>
        /// <param name="password"></param>
        /// <returns></returns>
        private string CheckPasswordStrength(string password)
        {
            StringBuilder sb = new StringBuilder();
            if (password.Length < 8)
                sb.Append("Minimum password length should be 8" + Environment.NewLine);
            if (!(Regex.IsMatch(password, "[A-Z]") && Regex.IsMatch(password, "[a-z]")
                  && Regex.IsMatch(password, "[0-9]")))
                sb.Append("Password should be AlphaNumeric" + Environment.NewLine);
            if (!(Regex.IsMatch(password, "[<,>,@,!,#,$,%,^,&,*,(,),_,+,\\[,\\],{,},?,:,;,|,',\\,.,/,~,`,=,]")))
                sb.Append("Password should Contain Special chars" + Environment.NewLine);
            return sb.ToString();

        }

        /// <summary>
        /// create JWT token
        /// </summary>
        /// <param name="user"></param>
        /// <param name="loginDto"></param>
        /// <returns></returns>
        private string CreateJwt(User user, loginDto loginDto)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("veryveryscret.....");
            var identity = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Role, user.Role),
                new Claim(ClaimTypes.Name, $"{user.Username}")
            });

            var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = identity,
                Expires = DateTime.Now.AddSeconds(loginDto.TokenExpiryTime),
                SigningCredentials = credentials
            };
            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
            return jwtTokenHandler.WriteToken(token);
        }

        /// <summary>
        /// create refresh token
        /// </summary>
        /// <returns></returns>
        private string CreateRefreshToken()
        {
            var randomNumber = new byte[32];
            using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                var refreshToken = Convert.ToBase64String(randomNumber);
                var tokenInUser = _appDbContext.Users.Any(a => a.RefreshToken == refreshToken);
                if (tokenInUser)
                {
                    return CreateRefreshToken();
                }
                return refreshToken;

            }
        }

        private ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            var key = Encoding.ASCII.GetBytes("veryveryscret.....");
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false, //you might want to validate the audience and issuer depending on your use case
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateLifetime = false //here we are saying that we don't care about the token's expiration date
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;
            if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Invalid token");
            return principal;
        }
    }
}
