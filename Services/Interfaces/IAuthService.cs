using JwtRefreshTokenCookieAuthExample.AuthModels;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace JwtRefreshTokenCookieAuthExample.Services.Interfaces
{
    public interface IAuthService
    {
        string HashPassword(
            string password);

        ClaimsPrincipal ValidateToken(
            string token);

        AuthClaims GetPayload(
            string token);

        RaTokens CreateRaTokens(
            Guid userId,
            bool persist = false);

        JwtToken GenerateJwtToken(
            AuthClaims authClaims,
            DateTime? expiration);

        Cookie CreateRefreshTokenCookie(
            JwtToken jwtToken = null,
            bool? persist = null);

        Cookie CreateAccessTokenCookie(
            JwtToken jwtToken = null,
            bool? persist = null);
    }
}
