using JwtRefreshTokenExampleWithCookies.Exceptions;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;

namespace JwtRefreshTokenExampleWithCookies.Models.Auth
{
    public class AuthClaims
    {
        public DateTime? iat { get; set; }
        public DateTime? exp { get; set; }
        public DateTime? nbf { get; set; }
        public Guid UserId { get; set; }
        public string Type { get; set; }
        public bool Persistent { get; set; }

        public AuthClaims() { }

        public AuthClaims(ClaimsPrincipal claimsPrincipal)
        {
            iat = DateTimeOffset.FromUnixTimeSeconds(TryGetClaim<long>(claimsPrincipal, nameof(iat))).UtcDateTime;
            exp = DateTimeOffset.FromUnixTimeSeconds(TryGetClaim<long>(claimsPrincipal, nameof(exp))).UtcDateTime;
            nbf = DateTimeOffset.FromUnixTimeSeconds(TryGetClaim<long>(claimsPrincipal, nameof(nbf))).UtcDateTime;
            UserId = Guid.Parse(TryGetClaim(claimsPrincipal, nameof(UserId)));
            Type = TryGetClaim(claimsPrincipal, nameof(Type));
            Persistent = TryGetClaim<bool>(claimsPrincipal, nameof(Persistent));
        }

        public ClaimsIdentity ToClaimsIdentity()
        {
            return new ClaimsIdentity(
                new List<Claim>
                {
                    new Claim(nameof(UserId), UserId.ToString()),
                    new Claim(nameof(Type), Type.ToString()),
                    new Claim(nameof(Persistent), Persistent.ToString()),
                }
            );
        }

        private static T TryGetClaim<T>(ClaimsPrincipal claimsPrincipal, string claimType)
        {
            var value = claimsPrincipal.FindFirstValue(claimType);
            if (value == null)
            {
                throw new ApiException();
            }
            try
            {
                return (T)Convert.ChangeType(value, typeof(T));
            }
            catch
            {
                throw new ApiException();
            }
        }

        private static string TryGetClaim(ClaimsPrincipal claimsPrincipal, string claimType)
        {
            var value = claimsPrincipal.FindFirstValue(claimType);
            if (value == null)
            {
                throw new ApiException();
            }
            return value;
        }
    }
}
