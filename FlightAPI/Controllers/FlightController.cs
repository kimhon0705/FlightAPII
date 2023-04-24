using FlightAPI.Models;
using FlightAPI.Services.FlightService;
using FlightAPI.Services.FlightService.DTO;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace FlightAPI.Controllers
{
    [Route("api/flight")]
    [ApiController]
    public class FlightController : ControllerBase
    {
        private readonly IFlightService _flightService;
        public FlightController(IFlightService flightService)
        {
            _flightService = flightService;
        }

        [HttpGet("flight-list")]
        public async Task<ActionResult<Flight>> GetAllFlight()
        {
            var result = await _flightService.GetAllFlight();
            if (result == null)
                return NotFound("There is no flight in the present.");

            return Ok(result);
        }

        [HttpPost("add-flight")]
        public async Task<ActionResult<Flight>>? AddFlight(AddFlightDTO request)
        {
            var result = await _flightService.AddFlight(request);
            if (result == null)
                return BadRequest("Flight creating failed !");

            return Ok(result);
        }

        [HttpPost("get-flight/{id}")]
        public async Task<ActionResult<Flight>>? GetFlightByID(int id)
        {
            var result = await _flightService.GetFlightByID(id);
            if (result == null)
                return NotFound("Can't find the Flight ID.");

            return Ok(result);
        }

        [HttpPost("{search}")]
        public async Task<ActionResult<List<Flight>>>? GetFlightBySearch(string search)
        {
            var result = await _flightService.GetFlightBySearch(search);
            if (result == null)
                return NotFound("The data is null or can't find your request.");

            return Ok(result);
        }

        [HttpDelete("delete-flight/{id}"), Authorize(Roles = "Admin")]
        public async Task<ActionResult<Flight>>? DeleteFlight(int id)
        {
            var result = await _flightService.DeleteFlight(id);
            if (result == null)
                return NotFound("Can't find the flight id or delete failed.");

            return Ok("Delete sucessfully.");
        }

    }
}
