using Microsoft.Build.Framework;

namespace FlightAPI.Services.GroupService.DTO
{
    public class AddGroupDTO
    {
        [Required]
        public string GroupName { get; set; } = string.Empty;

        [Required]        
        public string Note { get; set; } = string.Empty;
    }
}
