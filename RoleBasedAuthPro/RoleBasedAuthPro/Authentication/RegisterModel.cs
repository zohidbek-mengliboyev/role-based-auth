using System.ComponentModel.DataAnnotations;

namespace RoleBasedAuthPro.Authentication
{
    public class RegisterModel
    {
        [Required(ErrorMessage = "UserName is required")]
        public string UserName { get; set; }

        [Required(ErrorMessage = "Email is required")]
        public string Email { get; set; }

        [Required(ErrorMessage = "PassWord is required")]
        public string PassWord { get; set; }
    }
}
