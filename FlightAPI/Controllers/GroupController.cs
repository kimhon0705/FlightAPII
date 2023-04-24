using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using FlightAPI.DatabaseContext;
using FlightAPI.Models;
using FlightAPI.Services.GroupService;
using FlightAPI.Services.GroupService.DTO;
using Microsoft.AspNetCore.Authorization;

namespace FlightAPI.Controllers
{
    [Route("api/group")]
    [ApiController]
    public class GroupController : ControllerBase
    {
        private readonly IGroupService _groupService;

        public GroupController(IGroupService groupService)
        {
            _groupService = groupService;
        }

        [HttpGet("get-all-group")]
        public async Task<ActionResult<Group>>? GetAllGroup()
        {
            var result = await _groupService.GetAllGroup();
            if (result == null)
                return NotFound("The group data is null or not found");

            return Ok(result);
        }

        [HttpGet("get-group-by-id/{id}")]
        public async Task<ActionResult<Group>>? GetGroupByID(int id)
        {
            var result = await _groupService.GetGroupByID(id);
            if (result == null)
                return NotFound("Can't find your group id");

            return Ok(result);
        }

        [HttpPost("add-group")]
        public async Task<ActionResult<Group>>? AddGroup(AddGroupDTO request)
        {
            var result = await _groupService.AddGroup(request);
            if (result == null)
                return BadRequest("Add group item failed.");

            return Ok(result);
        }

        [HttpDelete("delete-group/{id}"), Authorize(Roles = "Admin")]
        public async Task<ActionResult<Group>>? DeleteGroup(int id)
        {
            var result = await _groupService.DeleteGroup(id);
            if (result == null)
                return NotFound("The group item is not exist.");

            return Ok("Delete sucessfully.");
        }
    }
}
