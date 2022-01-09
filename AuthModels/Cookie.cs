using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace JwtRefreshTokenCookieAuthExample.AuthModels
{
    public class Cookie
    {
        public string Key { get; set; }
        public string Value { get; set; }
        public CookieOptions Options { get; set; }

        public Cookie AppendToResponse(HttpResponse httpResponse)
        {
            httpResponse.Cookies.Append(Key, Value, Options);
            return this;
        }

        public Cookie DeleteFromResponse(HttpResponse httpResponse)
        {
            httpResponse.Cookies.Delete(Key, Options);
            return this;
        }
    }
}
