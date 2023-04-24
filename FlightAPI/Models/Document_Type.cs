using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace FlightAPI.Models
{
    public class Document_Type
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }
        public string Type_Name { get; set; } = string.Empty;
        public DateTime CreateDate { get; set; }
        public string Note { get; set; } = string.Empty;

    }
}
