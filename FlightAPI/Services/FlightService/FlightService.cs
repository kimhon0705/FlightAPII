using AutoMapper;
using FlightAPI.DatabaseContext;
using FlightAPI.Models;
using FlightAPI.Services.DocumentService.DTO;
using FlightAPI.Services.FlightService.DTO;
using Microsoft.EntityFrameworkCore;
using Microsoft.VisualBasic;

namespace FlightAPI.Services.FlightService
{
    public class FlightService : IFlightService
    {
        private readonly FlightDbContext _dbContext;
        private readonly IMapper _mapper;

        public FlightService(FlightDbContext dbContext, IMapper mapper)
        {
            _dbContext = dbContext;
            _mapper = mapper;
        }

        public async Task<List<Flight>>? GetAllFlight()
        {
            // return Ok(heroes.Select(hero => _mapper.Map<SuperHeroDto>(hero)));
            var flights = await _dbContext.Flights.Include(d => d.Documents).ToListAsync();
            if (flights == null)
                return null;

            return flights;
        }

        public async Task<Flight>? GetFlightByID(int id)
        {
            var flight = await _dbContext.Flights.FindAsync(id);
            if (flight == null)
                return null;

            return flight;
        }

        public async Task<List<Flight>>? GetFlightBySearch(string search)
        {
            List<Flight> flights = await _dbContext.Flights.Where(f => f.FlightCode.Contains(search) || f.LocationFrom.Contains(search)
            || f.LocationTo.Contains(search) || f.DepartureDate.ToString().Contains(search)).Include(d => d.Documents).ToListAsync();

            if (flights.Count() == 0)
                return null;

            return flights;
        }

        public async Task<Flight>? AddFlight(AddFlightDTO request)
        {
            if (_dbContext.Flights.Any(f => f.FlightCode == request.FlightCode))
                return null;

            var newFlight = new Flight()
            {
                FlightCode = request.FlightCode,
                LocationFrom = request.LocationFrom,
                LocationTo = request.LocationTo,
                DepartureDate = request.DepartureDate
            };

            _dbContext.Flights.Add(newFlight);
            await _dbContext.SaveChangesAsync();

            return newFlight;
        }

        public async Task<Flight>? DeleteFlight(int id)
        {
            var flight = await _dbContext.Flights.FindAsync(id);
            if (flight == null)
                return null;

            _dbContext.Flights.Remove(flight);
            await _dbContext.SaveChangesAsync();

            return flight;
        }


    }
}
