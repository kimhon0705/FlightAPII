using FlightAPI.Models;
using Microsoft.EntityFrameworkCore;

namespace FlightAPI.DatabaseContext
{
    public class FlightDbContext: DbContext
    {
        public FlightDbContext(DbContextOptions<FlightDbContext> options): base(options) { }

        public FlightDbContext() { }

        public DbSet<Role> Roles { get; set; }
        public DbSet<User> Users { get; set; }
        public DbSet<Document_Type> DocumentTypes { get; set; }
        public DbSet<Document> Documents { get; set; }
        public DbSet<DocumentFile> DocumentFiles { get; set; }
        public DbSet<Group> Groups { get; set; }
        public DbSet<Flight> Flights { get; set; }

        
    }
}
