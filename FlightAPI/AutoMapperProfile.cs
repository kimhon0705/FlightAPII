using AutoMapper;
using FlightAPI.Models;
using FlightAPI.Services.FlightService.DTO;

namespace FlightAPI
{
    public class AutoMapperProfile: Profile
    {
        public AutoMapperProfile() 
        { 
            CreateMap<Flight, FlightViewDTO>().ReverseMap();
        }
    }
}
