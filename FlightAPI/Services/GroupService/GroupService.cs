using FlightAPI.DatabaseContext;
using FlightAPI.Models;
using FlightAPI.Services.GroupService.DTO;
using Microsoft.EntityFrameworkCore;

namespace FlightAPI.Services.GroupService
{
    public class GroupService: IGroupService
    {
        private readonly FlightDbContext _dbContext;
        public GroupService(FlightDbContext dbContext) 
        {
            _dbContext = dbContext;
        }

        public async Task<List<Group>>? GetAllGroup()
        {
            var groups = await _dbContext.Groups.ToListAsync();
            if (groups == null)
                return null;

            return groups;
        }

        public async Task<Group>? GetGroupByID(int id)
        {
            var group = await _dbContext.Groups.FindAsync(id);
            if (group == null)
                return null;

            return group;
        }

        public async Task<Group>? AddGroup(AddGroupDTO request)
        {
            if (_dbContext.Groups.Any(g => g.GroupName == request.GroupName))
                return null;

            var newGroup = new Group()
            {
                GroupName = request.GroupName,
                Note = request.Note,
                CreateDate = DateTime.Now
            };

            _dbContext.Groups.Add(newGroup);
            await _dbContext.SaveChangesAsync();

            return newGroup;
        }

        public async Task<Group>? DeleteGroup(int id)
        {
            var group = await _dbContext.Groups.FindAsync(id);
            if (group == null)
                return null;

            _dbContext.Groups.Remove(group);
            await _dbContext.SaveChangesAsync();

            return group;
        }
    }
}
