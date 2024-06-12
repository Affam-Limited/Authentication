namespace Authentication.Models
{
    public class Admin
    {
        public string? userName {  get; set; }
        public string? Email { get; set; }
        public string password { get; set; }

       public bool IsAdmin { get; set; } = false;
       
    }
}
