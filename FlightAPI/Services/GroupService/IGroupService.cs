using FlightAPI.Models;
using FlightAPI.Services.GroupService.DTO;

namespace FlightAPI.Services.GroupService
{
    public interface IGroupService
    {
        Task<List<Group>>? GetAllGroup();
        Task<Group>? GetGroupByID(int id);
        Task<Group>? AddGroup(AddGroupDTO request);
        Task<Group>? DeleteGroup(int id);
    }
}
