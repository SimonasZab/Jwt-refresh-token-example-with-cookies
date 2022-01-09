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
        public long iat { get; set; }
        public Guid UserId { get; set; }
        public string Type { get; set; }
        public bool Persistent { get; set; }

        public AuthClaims() { }

        public AuthClaims(ClaimsPrincipal claimsPrincipal) : this(claimsPrincipal.Claims)
        {
        }

        public AuthClaims(IEnumerable<Claim> claims)
        {
            iat = TryGetClaim<long>(claims, nameof(iat));
            UserId = Guid.Parse(TryGetClaim(claims, nameof(UserId)));
            Type = TryGetClaim(claims, nameof(Type));
            Persistent = TryGetClaim<bool>(claims, nameof(Persistent));
        }

        public ClaimsIdentity ToClaimsIdentity()
        {
            return new ClaimsIdentity(
                new List<Claim>
                {
                    new Claim(nameof(iat), iat.ToString()),
                    new Claim(nameof(UserId), UserId.ToString()),
                    new Claim(nameof(Type), Type.ToString()),
                    new Claim(nameof(Persistent), Persistent.ToString()),
                }
            );
        }

        private static T TryGetClaim<T>(IEnumerable<Claim> claims, string name)
        {
            var claim = claims.FirstOrDefault(x => x.Type == name);
            if (claim == null)
            {
                throw new ApiException();
            }
            try
            {
                return (T)Convert.ChangeType(claim.Value, typeof(T));
            }
            catch
            {
                throw new ApiException();
            }
        }

        private static string TryGetClaim(IEnumerable<Claim> claims, string name)
        {
            var claim = claims.FirstOrDefault(x => x.Type == name);
            if (claim == null)
            {
                throw new ApiException();
            }
            return claim.Value;
        }
    }
}
