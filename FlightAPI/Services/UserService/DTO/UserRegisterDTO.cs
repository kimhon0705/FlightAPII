using System.ComponentModel.DataAnnotations;

namespace FlightAPI.Services.UserService.DTO
{
    public class UserRegisterDTO
    {
        [Required]
        public string UserName { get; set; } = string.Empty;

        [Required]
        [EmailAddress(ErrorMessage = "Please check your email address !")]
        public string Email { get; set; } = string.Empty;

        [Required]
        [Phone(ErrorMessage = "Please check your phone number !" )]
        public string Phone { get; set; } = string.Empty;

        [Required, MinLength(6, ErrorMessage = "Please enter at least 6 characters !")]
        public string Password { get; set; } = string.Empty;

        [Required, Compare("Password")]
        public string ConfirmPassword { get; set; } = string.Empty;
    }
}
