using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthApi.Models
{
    public class loginDto
    {
        public string? Username { get; set; }
        public string? Password { get; set; }
        public int TokenExpiryTime { get; set; }
    }
}
