using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace JwtRefreshTokenCookieAuthExample.AuthModels
{
    public class JwtToken
    {
        public string Value { get; set; }
        public DateTime? ExpiryDate { get; set; }
        public AuthClaims AuthClaims { get; set; }
    }
}
