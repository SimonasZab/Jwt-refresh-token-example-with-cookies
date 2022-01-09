using JwtRefreshTokenCookieAuthExample.AuthModels;
using JwtRefreshTokenCookieAuthExample.Exceptions;
using JwtRefreshTokenCookieAuthExample.Models.Settings;
using JwtRefreshTokenCookieAuthExample.Services.Interfaces;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace JwtRefreshTokenCookieAuthExample.Services
{
    public class AuthService : IAuthService
    {
        private readonly TokenValidationParameters TokenValidationParameters;
        private readonly TokenValidationParameters TokenValidationParametersWithoutLifetime;
        private readonly SigningCredentials SigningCredentials;
        private readonly AppSettings _appSettings;

        public AuthService(
            AppSettings appSettings)
        {
            _appSettings = appSettings;

            var symmetricSecurityKey = new SymmetricSecurityKey(appSettings.Auth.JwtSecret);
            TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = symmetricSecurityKey,
                ValidateIssuer = false,
                ValidateAudience = false,
                RequireExpirationTime = true,
                ValidateLifetime = true,
                LifetimeValidator = LifetimeValidator,
            };
            TokenValidationParametersWithoutLifetime = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = symmetricSecurityKey,
                ValidateIssuer = false,
                ValidateAudience = false,
                RequireExpirationTime = true,
                ValidateLifetime = false,
            };
            SigningCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha512Signature);
        }

        public string HashPassword(
            string password)
        {
            string hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password: password,
                salt: _appSettings.Auth.Salt,
                prf: KeyDerivationPrf.HMACSHA512,
                iterationCount: 100000,
                numBytesRequested: 256 / 8));

            return hashed;
        }

        public ClaimsPrincipal ValidateToken(
            string token)
        {
            return ValidateToken(
                token,
                TokenValidationParameters);
        }

        public AuthClaims GetPayload(
            string token)
        {
            var claimsPrincipal = ValidateToken(
                token,
                TokenValidationParametersWithoutLifetime);

            return new AuthClaims(claimsPrincipal);
        }

        private ClaimsPrincipal ValidateToken(
            string token,
            TokenValidationParameters parameters)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            try
            {
                var claimsPrincipal = jwtTokenHandler.ValidateToken(token, parameters, out SecurityToken securityToken);
                if (securityToken is JwtSecurityToken jwtRefrehSecurityToken)
                {
                    if (!jwtRefrehSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha512, StringComparison.InvariantCultureIgnoreCase))
                    {
                        throw new Exception();
                    }
                }
                else
                {
                    throw new Exception();
                }
                return claimsPrincipal;
            }
            catch
            {
                throw new ApiException();
            }
        }

        public RaTokens CreateRaTokens(
            Guid userId,
            bool persist = false)
        {
            var dto = new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero);

            AuthClaims accessTokenPayload = new AuthClaims
            {
                UserId = userId,
                iat = dto.ToUnixTimeMilliseconds(),
                Type = _appSettings.Auth.AccessTokenCookieName,
            };

            AuthClaims refreshTokenPayload = new AuthClaims
            {
                UserId = userId,
                iat = dto.ToUnixTimeMilliseconds(),
                Type = _appSettings.Auth.RefreshTokenCookieName,
                Persistent = persist,
            };

            DateTime? accessTokenExpirationDate = AccessTokenExpirationFromNow();
            DateTime? refreshTokenExpirationDate = RefreshTokenExpirationFromNow();

            JwtToken AccessToken = GenerateJwtToken(
                accessTokenPayload,
                accessTokenExpirationDate);
            JwtToken RefreshToken = GenerateJwtToken(
                refreshTokenPayload,
                refreshTokenExpirationDate);
            return new RaTokens(AccessToken, RefreshToken);
        }

        public JwtToken GenerateJwtToken(
            AuthClaims authClaims,
            DateTime? expiration)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = authClaims.ToClaimsIdentity(),
                Expires = expiration,
                SigningCredentials = SigningCredentials,
            };
            var token = jwtTokenHandler.CreateToken(tokenDescriptor);

            return new JwtToken
            {
                Value = jwtTokenHandler.WriteToken(token),
                ExpiryDate = expiration,
                AuthClaims = authClaims
            };
        }

        private DateTime AccessTokenExpirationFromNow() =>
            DateTime.UtcNow.AddMinutes(_appSettings.Auth.AccessTokenValidityInMinutes);

        private DateTime RefreshTokenExpirationFromNow() =>
            DateTime.UtcNow.AddDays(_appSettings.Auth.RefreshTokenValidityInDays);

        public Cookie CreateRefreshTokenCookie(
            JwtToken jwtToken = null,
            bool? persist = null)
        {
            Cookie refreshTokenCookie = CreateTokenCookie(
                _appSettings.Auth.RefreshTokenCookieName,
                jwtToken,
                persist);
            refreshTokenCookie.Options.Path =  "/auth";
            return refreshTokenCookie;
        }

        public Cookie CreateAccessTokenCookie(
            JwtToken jwtToken = null,
            bool? persist = null) =>
            CreateTokenCookie(
                _appSettings.Auth.AccessTokenCookieName,
                jwtToken,
                persist);

        private static Cookie CreateTokenCookie(
            string key,
            JwtToken jwtToken,
            bool? persist = null)
        {
            CookieOptions cookieOptions = new CookieOptions();
            if (jwtToken == null)
            {
                jwtToken = new JwtToken();
                cookieOptions.Expires = null;
            }
            else
            {
                cookieOptions.Expires = persist == true ? jwtToken.ExpiryDate : null;
            }

            Cookie cookie = new Cookie
            {
                Key = key,
                Value = jwtToken.Value,
                Options = cookieOptions
            };
            return cookie;
        }

        private bool LifetimeValidator(
            DateTime? notBefore,
            DateTime? expires,
            SecurityToken securityToken,
            TokenValidationParameters validationParameters)
        {
            return DateTime.UtcNow < expires;
        }
    }
}
