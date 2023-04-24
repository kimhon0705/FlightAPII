using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace FlightAPI.Models
{
    public class Flight
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }

        public string FlightCode { get; set; } = string.Empty;

        public string LocationFrom { get; set; } = string.Empty;

        public string LocationTo { get; set; } = string.Empty;

        public DateTime DepartureDate { get; set; }

       
        public List<Document> Documents { get; set; }
        
    }
}
