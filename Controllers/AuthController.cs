using JwtRefreshTokenExampleWithCookies.Exceptions;
using JwtRefreshTokenExampleWithCookies.Models.Request;
using JwtRefreshTokenExampleWithCookies.Models.Response;
using JwtRefreshTokenExampleWithCookies.Models.Settings;
using JwtRefreshTokenExampleWithCookies.Services.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace JwtRefreshTokenExampleWithCookies.Controllers
{

    [ApiController]
    [Route("[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly MainDbContext _mainDbContext;
        private readonly AppSettings _appSettings;
        private readonly IAuthService _authService;

        public AuthController(
            MainDbContext mainDbContext,
            AppSettings appSettings,
            IAuthService authService)
        {
            _mainDbContext = mainDbContext;
            _appSettings = appSettings;
            _authService = authService;
        }

        [HttpPost("login")]
        public async Task<ActionResult<LoginResponse>> Login(
            LoginRequest body)
        {
            var user = await _mainDbContext.Users
                .FirstOrDefaultAsync(x => x.Email == body.Email);

            if (user == null)
            {
                throw new ApiException("Invalid email or password");
            }

            string hashedPassword = _authService.HashPassword(body.Password);

            if (hashedPassword != user.Password)
            {
                throw new ApiException("Invalid email or password");
            }

            var jwtTokens = _authService.CreateRaTokens(
                user.Id,
                body.Persist);

            user.RefreshToken = jwtTokens.RefreshToken.Value;
            user.RefreshTokenExpiryDate = jwtTokens.RefreshToken.ExpiryDate;
            await _mainDbContext.SaveChangesAsync();

            var accessTokenCookie = _authService.CreateAccessTokenCookie(
                jwtTokens.AccessToken,
                body.Persist)
                .AppendToResponse(HttpContext.Response);

            var refreshTokenCookie = _authService.CreateRefreshTokenCookie(
                jwtTokens.RefreshToken,
                body.Persist)
                .AppendToResponse(HttpContext.Response);

            var response = new LoginResponse
            {
                AccessTokenExpiryDate = jwtTokens.AccessToken.ExpiryDate,
                RefreshTokenExpiryDate = jwtTokens.RefreshToken.ExpiryDate,
            };

            return Ok(response);
        }

        [HttpPost("logout")]
        public async Task<ActionResult> Logout(
            [FromServices] AppSettings appSettings)
        {
            Request.Cookies.TryGetValue(
                appSettings.Auth.RefreshTokenCookieName,
                out string? refreshToken);

            if (refreshToken == null)
            {
                throw new ApiException("Invalid cookie");
            }

            var authClaims = _authService.GetPayload(refreshToken);

            var user = await _mainDbContext.Users
                .FirstOrDefaultAsync(x => x.Id == authClaims.UserId);

            if (user == null)
            {
                throw new ApiException("User not found");
            }

            user.RefreshToken = null;
            user.RefreshTokenExpiryDate = null;
            await _mainDbContext.SaveChangesAsync();

            _authService.CreateAccessTokenCookie()
                .DeleteFromResponse(HttpContext.Response);

            _authService.CreateRefreshTokenCookie()
                .DeleteFromResponse(HttpContext.Response);

            return Ok();
        }

        [HttpPost("refresh")]
        public async Task<ActionResult> Refresh(
            [FromServices] AppSettings appSettings)
        {
            Request.Cookies.TryGetValue(
                appSettings.Auth.RefreshTokenCookieName,
                out string? refreshToken);

            if (refreshToken == null)
            {
                throw new ApiException("Invalid cookie");
            }

            var authClaims = _authService.GetPayload(refreshToken);

            var user = await _mainDbContext.Users
                .FirstOrDefaultAsync(x => x.Id == authClaims.UserId);

            if (user == null)
            {
                throw new ApiException("User not found");
            }

            if (refreshToken != user.RefreshToken)
            {
                throw new ApiException("Invalid token");
            }

            if (user.RefreshTokenExpiryDate < DateTime.UtcNow)
            {
                throw new ApiException("Refresh token is expired");
            }

            var jwtTokens = _authService.CreateRaTokens(
                user.Id,
                authClaims.Persistent);

            user.RefreshToken = jwtTokens.RefreshToken.Value;
            user.RefreshTokenExpiryDate = jwtTokens.RefreshToken.ExpiryDate;
            await _mainDbContext.SaveChangesAsync();

            var accessTokenCookie = _authService.CreateAccessTokenCookie(
                jwtTokens.AccessToken,
                authClaims.Persistent)
                .AppendToResponse(HttpContext.Response);

            var refreshTokenCookie = _authService.CreateRefreshTokenCookie(
                jwtTokens.RefreshToken,
                authClaims.Persistent)
                .AppendToResponse(HttpContext.Response);

            var response = new RefreshResponse
            {
                AccessTokenExpiryDate = jwtTokens.AccessToken.ExpiryDate,
                RefreshTokenExpiryDate = jwtTokens.RefreshToken.ExpiryDate,
            };

            return Ok(response);
        }
    }
}
