using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace JwtRefreshTokenExampleWithCookies.Models.Auth
{
    public class RaTokens
    {
        public JwtToken AccessToken { get; set; }
        public JwtToken RefreshToken { get; set; }

        public RaTokens(JwtToken accessToken, JwtToken refreshToken)
        {
            AccessToken = accessToken;
            RefreshToken = refreshToken;
        }
    }
}
