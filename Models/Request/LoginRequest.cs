﻿using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace JwtRefreshTokenCookieAuthExample.Models.Request
{
    public class LoginRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
        [MinLength(8)]
        [Required]
        public string Password { get; set; }
        public bool Persist { get; set; } = false;
    }
}