using FlightAPI.Models;
using FlightAPI.Services.DocumentTypeService.DTO;

namespace FlightAPI.Services.DocumentTypeService
{
    public interface IDocumentTypeService
    {
        Task<List<Document_Type>>? GetAllDocumentType();
        Task<Document_Type>? GetDocumentTypeByID(int id);
        Task<Document_Type>? AddDocumentType(AddDocumentTypeDTO documentType);
        Task<Document_Type>? DeleteDocumentType(int id);
    }
}
