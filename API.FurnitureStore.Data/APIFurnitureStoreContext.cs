using API.FurnitureStore.Shared;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace API.FurnitureStore.Data
{
    //Esta clase debe heredar de dBcontext
    public class APIFurnitureStoreContext : IdentityDbContext
    {
        // -- CONFIGURACION DE EF --
        //Un constructor que recibe parametros desde 'afuera' desde 'DbContext'
        //Ademas debe llamar a un constructor de la clase 'DbCOntext
        //y tamb le paso 'options' como parámetro. 
        public APIFurnitureStoreContext(DbContextOptions options) : base(options) { }
        
        //Creamos una propiedad 'DbSet', es una clase de EF. Es una
        //representación de la tabla de los modelos y desde alli EF hace el proceso.

        public DbSet<Client> Clients { get; set; }
        public DbSet<Product> Products { get; set; }
        public DbSet<Order> Orders { get; set; }
        public DbSet<ProductCategory> ProductCategories { get; set; }
        public DbSet<OrderDetail> OrderDetails { get; set; }
        public DbSet<RefreshToken> RefreshToken { get; set; }

        //Configuracion de SQLite. Sobrescribe un metodo inicial de 'DbContext' para que 
        //tome la configuracion especifica de la persistencia con 'Sqlite';
        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            optionsBuilder.UseSqlite(); //Pedimos que el parametro que toma sea con 'Sqlite'
        }
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
            modelBuilder.Entity<OrderDetail>().HasKey(od => new { od.OrderId, od.ProductId });
        }
    }
}
