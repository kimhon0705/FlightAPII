using FlightAPI.Models;

namespace FlightAPI.Services.FlightService.DTO
{
    public class FlightViewDTO
    {
        public string FlightCode { get; set; } = string.Empty;

        public string LocationFrom { get; set; } = string.Empty;

        public string LocationTo { get; set; } = string.Empty;

        public DateTime DepartureDate { get; set; }

        public List<Document> Documents { get; set; }
    }
}
