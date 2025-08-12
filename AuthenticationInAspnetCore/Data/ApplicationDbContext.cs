using AuthenticationInAspnetCore.Entities;
using Microsoft.EntityFrameworkCore;

namespace AuthenticationInAspnetCore.Data
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }
         public DbSet<User> Users { get; set; }

        // public DbSet<Role> Roles { get; set; }
        // public DbSet<Claim> Claims { get; set; }
        //protected override void OnModelCreating(ModelBuilder modelBuilder)
        //{
        //    base.OnModelCreating(modelBuilder);
        //}
    }
}