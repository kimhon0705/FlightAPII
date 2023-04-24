using System.ComponentModel.DataAnnotations;

namespace FlightAPI.Services.DocumentTypeService.DTO
{
    public class AddDocumentTypeDTO
    {
        [Required]
        public string Type_Name { get; set; } = string.Empty;

        [Required]
        public string Note { get; set; } = string.Empty;
    }
}
