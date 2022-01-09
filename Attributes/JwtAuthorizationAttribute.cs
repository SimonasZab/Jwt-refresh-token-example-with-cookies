using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace JwtRefreshTokenCookieAuthExample.Attributes
{
    public class JwtAuthorizationAttribute : TypeFilterAttribute
    {
        public JwtAuthorizationAttribute() : base(typeof(JwtAuthorizationFilter))
        {
        }
    }
}
