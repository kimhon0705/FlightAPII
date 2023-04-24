using FlightAPI.DatabaseContext;
using FlightAPI.Models;
using FlightAPI.Services.DocumentFileService;
using FlightAPI.Services.DocumentFileService.DTO;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.EntityFrameworkCore;
using System.IO.Compression;

namespace FlightAPI.Controllers
{
    [Route("api/document-file")]
    [ApiController]
    public class DocumentFileController : ControllerBase
    {
        private readonly IDocumentFileService _documentFileService;
        private readonly FlightDbContext _dbContext;
        public DocumentFileController(IDocumentFileService documentFileService, FlightDbContext dbContext)
        {
            _documentFileService = documentFileService;
            _dbContext = dbContext;
        }

        [HttpPost("upload-file")]
        public async Task<ActionResult<DocumentFile>>? AddDocumentFile([FromForm] DocumentFileWithFormFile formFile)
        {
            var result = await _documentFileService.AddDocumentFile(formFile);
            if (result == null)
                return BadRequest("Can't add the document file.");

            return Ok(result);
        }

        [HttpPost("export-file/{fileName}")]
        public async Task<IActionResult> DownloadDocumentFileByFileName(string fileName)
        {
            var findDocumentFileObject = _dbContext.DocumentFiles.Where(f => f.FileName == fileName).FirstOrDefault();
            if (findDocumentFileObject == null)
                return NotFound("Can't find the file name data.");

            var fileNameURL = Convert.ToString(findDocumentFileObject.Url);

            var fileNameDocumentFile = Path.GetFileName(fileNameURL);

            var filePath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot\\files", fileNameDocumentFile);

            var provider = new FileExtensionContentTypeProvider();
            if (!provider.TryGetContentType(filePath, out var contentType))
            {
                contentType = "application/octet-stream";
            }

            var bytes = await System.IO.File.ReadAllBytesAsync(filePath);

            return File(bytes, contentType, Path.GetFileName(filePath));
        }

        [HttpPost("get-file/{id}")]
        public async Task<ActionResult<DocumentFile>>? GetDocumentFileByID(int id)
        {
            var result = await _documentFileService.GetDocumentFileByID(id);
            if (result == null)
                return NotFound("Can't find the document file or not exist.");

            return Ok(result);
        }

        [HttpDelete("delete-file/{id}"), Authorize(Roles = "Admin")]
        public async Task<ActionResult<DocumentFile>>? DeleteDocumentFileByID(int id)
        {
            var result = await _documentFileService.DeleteDocumentFileByID(id);
            if (result == null)
                return BadRequest("Can't delete document file or it's not exist.");

            return Ok("Delete document file successfully.");
        }

       
    }
}
