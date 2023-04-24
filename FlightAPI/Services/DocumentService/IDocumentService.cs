using FlightAPI.Models;
using FlightAPI.Services.DocumentService.DTO;

namespace FlightAPI.Services.DocumentService
{
    public interface IDocumentService
    {
        Task<List<Document>>? GetAllDocument();
        Task<Document>? GetDocumentById(int id);
        Task<List<Document>>? GetDocumentBySearch(string search);
        Task<Document>? AddDocument(AddDocumentDTO document);

        Task<List<Document>>? DeleteDocument(int id);
    }
}
