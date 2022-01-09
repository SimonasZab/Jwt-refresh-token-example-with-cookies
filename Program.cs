using JwtRefreshTokenCookieAuthExample;
using JwtRefreshTokenCookieAuthExample.Models.Db;
using JwtRefreshTokenCookieAuthExample.Models.Settings;
using JwtRefreshTokenCookieAuthExample.Services;
using JwtRefreshTokenCookieAuthExample.Services.Interfaces;
using Microsoft.AspNetCore.CookiePolicy;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

var appSettings = builder.Configuration.Get<AppSettings>();
builder.Services.AddSingleton(appSettings);

builder.Services.Configure<CookiePolicyOptions>(options =>
{
    options.MinimumSameSitePolicy = SameSiteMode.Strict;
    options.Secure = CookieSecurePolicy.Always;
    options.HttpOnly = HttpOnlyPolicy.Always;
});

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddSingleton<IAuthService, AuthService>();

builder.Services.AddDbContext<MainDbContext>(options =>
    options.UseInMemoryDatabase("JwtRefreshTokenCookieAuthTestDb"));

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.UseCookiePolicy();

app.MapControllers();

//Seed test user
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    var dbContext = services.GetService<MainDbContext>();
    var authService = services.GetService<IAuthService>();

    dbContext.Users.Add(
        new User
        {
            Id = Guid.Parse("68973d4a-c5a9-4718-b843-0503c2b3bac2"),
            Email = "fakeemail@fakeurl.com",
            Password = authService.HashPassword("passworD1")
        });
    dbContext.SaveChanges();
}

app.Run();