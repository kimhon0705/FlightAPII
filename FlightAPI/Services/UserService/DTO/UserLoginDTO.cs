using System.ComponentModel.DataAnnotations;

namespace FlightAPI.Services.UserService.DTO
{
    public class UserLoginDTO
    {
        [Required]
        public string Email { get; set; } = string.Empty;
        [Required]
        public string Password { get; set; } = string.Empty;
    }
}
