using JwtRefreshTokenCookieAuthExample.AuthModels;
using JwtRefreshTokenCookieAuthExample.Models.Settings;
using JwtRefreshTokenCookieAuthExample.Services.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace JwtRefreshTokenCookieAuthExample.Attributes
{
    public class JwtAuthorizationFilter : IAsyncAuthorizationFilter
    {
        private readonly AppSettings _appSettings;
        private readonly IAuthService _authService;
        private readonly MainDbContext _dbContext;

        public JwtAuthorizationFilter(
            AppSettings appSettings,
            IAuthService authService,
            MainDbContext dbContext)
        {
            _appSettings = appSettings;
            _authService = authService;
            _dbContext = dbContext;
        }

        public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
        {
            try
            {
                context.HttpContext.Request.Cookies.TryGetValue(
                    _appSettings.Auth.AccessTokenCookieName,
                    out string? accessToken);

                if (accessToken == null)
                {
                    context.Result = new UnauthorizedResult();
                    return;
                }

                var claimsPrincipal = _authService.ValidateToken(accessToken);
                var authClaims = new AuthClaims(claimsPrincipal);

                if(authClaims.Type != _appSettings.Auth.AccessTokenCookieName)
                {
                    context.Result = new UnauthorizedResult();
                    return;
                }

                var user = await _dbContext.Users
                    .FirstOrDefaultAsync(x => x.Id == authClaims.UserId);

                if (user == null)
                {
                    context.Result = new UnauthorizedResult();
                    return;
                }

                context.HttpContext.User = claimsPrincipal;
            }
            catch(Exception ex)
            {
                context.Result = new UnauthorizedResult();
            }
        }
    }
}
