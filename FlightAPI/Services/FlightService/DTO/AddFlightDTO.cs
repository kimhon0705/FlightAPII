
namespace FlightAPI.Services.FlightService.DTO
{
    public class AddFlightDTO
    {
        public string FlightCode { get; set; } = string.Empty;

        public string LocationFrom { get; set; } = string.Empty;

        public string LocationTo { get; set; } = string.Empty;

        public DateTime DepartureDate { get; set; }
    }
}
