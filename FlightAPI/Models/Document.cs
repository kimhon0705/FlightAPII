using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace FlightAPI.Models
{
    public class Document
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public DateTime CreateDate { get; set; } = DateTime.Now;
        public string Note { get; set; } = string.Empty;
        public string Url { get; set; } = string.Empty;
        public string Version { get; set; } = string.Empty;


        [JsonIgnore]
        public Flight Flight { get; set; }
        public int FlightID { get; set; }

        [JsonIgnore]
        public Document_Type DocumentType { get; set; }
        public int Document_TypeID { get; set; }

        [JsonIgnore]
        public User User { get; set; }
        public int UserID { get; set; }

        [JsonIgnore]
        public Group Group { get; set; }
        public int GroupID { get; set; }

        
        public List<DocumentFile> DocumentFiles { get; set; }

    }
}