using JwtRefreshTokenCookieAuthExample.Models;
using JwtRefreshTokenCookieAuthExample.Models.Db;
using Microsoft.EntityFrameworkCore;

namespace JwtRefreshTokenCookieAuthExample
{
    public class MainDbContext : DbContext
    {
        public MainDbContext(DbContextOptions options) : base(options)
        {

        }

        public DbSet<User> Users { get; set; }
    }
}
