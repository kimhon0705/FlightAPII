using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using FlightAPI.Models;
using FlightAPI.Services.DocumentService;
using FlightAPI.Services.DocumentService.DTO;
using Microsoft.AspNetCore.Authorization;

namespace FlightAPI.Controllers
{
    [Route("api/document")]
    [ApiController]
    public class DocumentController : ControllerBase
    {
        private readonly IDocumentService _documentService;
        public DocumentController(IDocumentService documentService)
        {
            _documentService = documentService;
        }

        [HttpGet("get-all-document"), Authorize(Roles = "Admin")]
        public async Task<ActionResult<List<Document>>>? GetAllDocument()
        {
            var result = await _documentService.GetAllDocument();
            if (result == null) 
                return NotFound("Can't find the document data.");

            return Ok(result);
        }

        [HttpGet("get-document/{id}")]
        public async Task<ActionResult<Document>>? GetDocumentById(int id)
        {
            var result = await _documentService.GetDocumentById(id);
            if (result is null)
                return NotFound("Not Found Document");

            return Ok(result);
        }

        [HttpPost("{search}")]
        public async Task<ActionResult<List<Document>>>? GetDocumentBySearch(string search)
        {
            var result = await _documentService.GetDocumentBySearch(search);
            if (result is null)
                return NotFound("Can't find the document or it's not exist.");

            return Ok(result);
        }

        [HttpPost("add-document")]
        public async Task<ActionResult<Document>>? AddDocument( [FromForm] AddDocumentDTO document)
        {
            var result = await _documentService.AddDocument(document);
            if (result is null)
                return NotFound("Not Found Document");

            return Ok(result);
        }


        [HttpDelete("delete-document/{id}"), Authorize(Roles = "Admin")]
        public async Task<ActionResult<List<Document>>>? DeleteDocument(int id)
        {
            var result = await _documentService.DeleteDocument(id);
            if (result is null)
                return NotFound("Not Found Document");

            return Ok(result);
        }
    }
}
