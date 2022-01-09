using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace JwtRefreshTokenExampleWithCookies.Models.Response
{
    public class LoginResponse
    {
        public DateTime? AccessTokenExpiryDate { get; set; }
        public DateTime? RefreshTokenExpiryDate { get; set; }
    }
}
