using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using FlightAPI.DatabaseContext;
using FlightAPI.Models;
using FlightAPI.Services.DocumentTypeService;
using FlightAPI.Services.DocumentTypeService.DTO;
using Microsoft.AspNetCore.Authorization;

namespace FlightAPI.Controllers
{
    [Route("api/document-type")]
    [ApiController]
    public class Document_TypeController : ControllerBase
    {
        private readonly IDocumentTypeService _documentTypeService;

        public Document_TypeController(IDocumentTypeService documentTypeService)
        {
            _documentTypeService = documentTypeService;
        }

        [HttpGet("get-list")]
        public async Task<ActionResult<List<Document_Type>>>? GetAllDocumentType()
        {
            var result = await _documentTypeService.GetAllDocumentType();
            if (result == null)
                return NotFound("The data list is null.");

            return Ok(result);
        }

        [HttpGet("get-by-id/{id}")]
        public async Task<ActionResult<Document_Type>>? GetDocumentTypeByID(int id)
        {
            var result = await _documentTypeService.GetDocumentTypeByID(id);
            if (result == null)
                return NotFound("Can't find the Document type id.");

            return Ok(result);
        }

        [HttpPost("add")]
        public async Task<ActionResult<Document_Type>>? AddDocumentType(AddDocumentTypeDTO documentType)
        {
            var result = await _documentTypeService.AddDocumentType(documentType);
            if (result == null)
                return BadRequest("Add Document Type data failed.");

            return Ok(result);
        }

        [HttpDelete("delete/{id}"), Authorize(Roles = "Admin")]
        public async Task<ActionResult<Document_Type>>? DeleteDocumentType(int id)
        {
            var result = await _documentTypeService.DeleteDocumentType(id);
            if (result == null)
                return NotFound("Can't find the id or not exsit.");

            return Ok("Delete document type sucessfully.");
        }
    }
}
