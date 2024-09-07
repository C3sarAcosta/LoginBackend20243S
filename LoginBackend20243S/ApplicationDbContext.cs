using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace LoginBackend20243S
{
    public class ApplicationDbContext : IdentityDbContext
    {
        public ApplicationDbContext(DbContextOptions options) : base(options) 
        {
            //Configurar relaciones
        }

        //
        //public DbSet<Model> Plural { get; set; }
    }
}
