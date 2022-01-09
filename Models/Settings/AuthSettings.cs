using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace JwtRefreshTokenCookieAuthExample.Models.Settings
{
    public class AuthSettings
    {
        public byte[] Salt { get; set; }
        public byte[] JwtSecret { get; set; }
        public string RefreshTokenCookieName { get; set; }
        public string AccessTokenCookieName { get; set; }
        public int AccessTokenValidityInMinutes { get; set; }
        public int RefreshTokenValidityInDays { get; set; }
    }
}
