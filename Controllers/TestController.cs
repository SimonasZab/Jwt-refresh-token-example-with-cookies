using JwtRefreshTokenCookieAuthExample.Attributes;
using Microsoft.AspNetCore.Mvc;

namespace JwtRefreshTokenCookieAuthExample.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class TestController : ControllerBase
    {
        [JwtAuthorization]
        [HttpGet]
        public IActionResult Get()
        {
            return Ok("You are authorized");
        }
    }
}
