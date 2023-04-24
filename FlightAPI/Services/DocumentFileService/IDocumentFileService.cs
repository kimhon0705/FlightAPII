using FlightAPI.Models;
using FlightAPI.Services.DocumentFileService.DTO;
using Microsoft.AspNetCore.Mvc;

namespace FlightAPI.Services.DocumentFileService
{
    public interface IDocumentFileService
    {
        Task<DocumentFile>? AddDocumentFile([FromForm] DocumentFileWithFormFile formFile);
        Task<DocumentFile>? GetDocumentFileByID(int id);
        Task<DocumentFile>? DeleteDocumentFileByID(int id);

    }
}
