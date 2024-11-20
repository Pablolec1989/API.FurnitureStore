using API.FurnitureStore.Data;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using API.FurnitureStore.Shared;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;

namespace API.FurnitureStore.API.Controllers
{
    [Authorize] //Metodo para restringir el acceso
    [Route("api/[controller]")]
    [ApiController]
    public class ClientsController : ControllerBase
    {
        private readonly APIFurnitureStoreContext _context;
        public ClientsController(APIFurnitureStoreContext context)
        {
            _context = context;
        }

        /*[AllowAnonymous]*/ //Metodo que indica que no se requiere autorizacion para acceder
        [HttpGet]
        //Devolucion de listado de clientes
        public async Task<IEnumerable<Client>> Get()
        {
            return await _context.Clients.ToListAsync();
        }

        [HttpGet("{id}")]
        //Devolucion de un solo cliente
        public async Task<IActionResult> GetDetails(int id)
        {
            var client = await _context.Clients.FirstOrDefaultAsync(c => c.Id  == id);

            if (client == null) return NotFound(); //si el cliente no se encuentra devuelve error.

            return Ok(client); //http response 200.
        }
        [HttpPost]
        //Insertar cliente
        public async Task<IActionResult> Post(Client client)
        {
            await _context.Clients.AddAsync(client); //Agrego a la lista de la BD el cliente que viene por http
            await _context.SaveChangesAsync(); //guardamos

            return CreatedAtAction("Post", client.Id, client);
        }

        [HttpPut]
        public async Task<IActionResult> Put(Client client)
        {
            _context.Clients.Update(client);
            await _context.SaveChangesAsync();
            return NoContent();
        }

        [HttpDelete]
        public async Task<IActionResult> Delete(Client client)
        {
            if (client == null) return NotFound();
            _context.Clients.Remove(client);
            await _context.SaveChangesAsync();
            return NoContent();
        }
    } 
}
