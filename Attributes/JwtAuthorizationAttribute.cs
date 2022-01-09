using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace JwtRefreshTokenExampleWithCookies.Attributes
{
    public class JwtAuthorizationAttribute : TypeFilterAttribute
    {
        public JwtAuthorizationAttribute() : base(typeof(JwtAuthorizationFilter))
        {
        }
    }
}
