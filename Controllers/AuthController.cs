using JwtRefreshTokenExampleWithCookies.Exceptions;
using JwtRefreshTokenExampleWithCookies.Models.Auth;
using JwtRefreshTokenExampleWithCookies.Models.Request;
using JwtRefreshTokenExampleWithCookies.Models.Response;
using JwtRefreshTokenExampleWithCookies.Models.Settings;
using JwtRefreshTokenExampleWithCookies.Services.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

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
        public async Task<ActionResult> Logout()
        {
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
                throw new ApiException("Invalid refresh token");
            }

            ClaimsPrincipal claimsPrincipal;
            try
            {
                claimsPrincipal = _authService.ValidateToken(refreshToken);
            }
            catch
            {
                throw new ApiException("Invalid refresh token");
            }

            var authClaims = new AuthClaims(claimsPrincipal);

            var user = await _mainDbContext.Users
                .FirstOrDefaultAsync(x => x.Id == authClaims.UserId);

            if (user == null)
            {
                throw new ApiException("User not found");
            }

            var jwtTokens = _authService.CreateRaTokens(
                authClaims.UserId,
                authClaims.Persistent);

            var accessTokenCookie = _authService.CreateAccessTokenCookie(
                jwtTokens.AccessToken,
                authClaims.Persistent)
                .AppendToResponse(HttpContext.Response);

            var response = new RefreshResponse
            {
                AccessTokenExpiryDate = jwtTokens.AccessToken.ExpiryDate,
                RefreshTokenExpiryDate = authClaims.exp,
            };

            return Ok(response);
        }
    }
}
