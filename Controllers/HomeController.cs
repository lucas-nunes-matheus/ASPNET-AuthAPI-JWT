using ImobAPI;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace ImobAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class HomeController : ControllerBase
    {
        public HomeController()
        {
        }

        //api/home
        // Permite que todos os usuários autenticados como 'User' ou 'Admin' acessem esta rota
        [HttpGet]
        [Authorize(AuthenticationSchemes = "Bearer", Roles = nameof(RoleTypes.User) + "," + nameof(RoleTypes.Admin))]
        public IActionResult Health()
        {
            return Ok("Api is fine");
        }

        //api/home/admin
        [HttpGet("admin")]
        [Authorize(AuthenticationSchemes = "Bearer", Roles = nameof(RoleTypes.Admin))]
        public IActionResult AdminRoute()
        {
            return Ok("Admin route");
        }
    }
}
