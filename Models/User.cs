using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Globalization;
using System.IO;

namespace Authentication.Models
{
    public class User : IdentityUser
    {

        [MaxLength(50)]
        public string Name { get; set; }

        [Column]
        public DateTime CreatedDate { get; set; } = DateTime.Now;

        [Column]
        public DateTime ModifiedDate { get; set; } = DateTime.Now;

        [Column]
        public DateTime LastLogin { get; set; } = DateTime.Now;

        public bool IsAdmin { get; set; } = false;
    }
}
