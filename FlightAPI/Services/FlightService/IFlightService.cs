using FlightAPI.Models;
using FlightAPI.Services.FlightService.DTO;

namespace FlightAPI.Services.FlightService
{
    public interface IFlightService
    {
        Task<List<Flight>>? GetAllFlight();
        Task<Flight>? AddFlight(AddFlightDTO request);
        Task<Flight>? GetFlightByID(int id);
        Task<List<Flight>>? GetFlightBySearch(string search);
        Task<Flight>? DeleteFlight(int id);

    }
}
