using FlightAPI.DatabaseContext;
using FlightAPI.Models;
using FlightAPI.Services.DocumentTypeService.DTO;
using Microsoft.EntityFrameworkCore;

namespace FlightAPI.Services.DocumentTypeService
{
    public class DocumentTypeService: IDocumentTypeService
    {
        private readonly FlightDbContext _dbContext;
        public DocumentTypeService(FlightDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public async Task<List<Document_Type>>? GetAllDocumentType()
        {
            var documentTypes = await _dbContext.DocumentTypes.ToListAsync();
            if (documentTypes == null)
                return null;

            return documentTypes;
        }

        public async Task<Document_Type>? GetDocumentTypeByID(int id)
        {
            var documentType = await _dbContext.DocumentTypes.FindAsync(id);
            if (documentType == null)
                return null;

            return documentType;
        }

        public async Task<Document_Type>? AddDocumentType(AddDocumentTypeDTO documentType)
        {
            if (_dbContext.DocumentTypes.Any(d => d.Type_Name == documentType.Type_Name))
                return null;

            var newDocumentType = new Document_Type()
            {
                Type_Name = documentType.Type_Name,
                CreateDate = DateTime.Now,
                Note = documentType.Note,
            };

            _dbContext.DocumentTypes.Add(newDocumentType);
            await _dbContext.SaveChangesAsync();

            return newDocumentType;
        }

        public async Task<Document_Type>? DeleteDocumentType(int id)
        {
            var typeObject = await _dbContext.DocumentTypes.FindAsync(id);
            if (typeObject == null)
                return null;

            _dbContext.DocumentTypes.Remove(typeObject);
            await _dbContext.SaveChangesAsync();

            return typeObject;
        } 
    }
}
