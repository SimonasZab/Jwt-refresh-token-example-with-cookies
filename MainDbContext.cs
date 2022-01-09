using JwtRefreshTokenExampleWithCookies.Models;
using JwtRefreshTokenExampleWithCookies.Models.Db;
using Microsoft.EntityFrameworkCore;

namespace JwtRefreshTokenExampleWithCookies
{
    public class MainDbContext : DbContext
    {
        public MainDbContext(DbContextOptions options) : base(options)
        {

        }

        public DbSet<User> Users { get; set; }
    }
}
