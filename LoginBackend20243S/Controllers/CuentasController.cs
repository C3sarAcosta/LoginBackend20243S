using LoginBackend20243S.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace LoginBackend20243S.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class CuentasController :Controller
    {
        private readonly UserManager<IdentityUser> userManager;
        private readonly IConfiguration configuration;
        private readonly SignInManager<IdentityUser> signInManager;

        public CuentasController(UserManager<IdentityUser> userManager,
            IConfiguration configuration,
            SignInManager<IdentityUser> signInManager)
        {
            this.userManager = userManager;
            this.configuration = configuration;
            this.signInManager = signInManager;
        }

        private async Task<RespuestaAuthentication> ConstruirToken(CredencialesUsuario credencialesUsuario)
        {
            var claims = new List<Claim>
            {
                new Claim("email", credencialesUsuario.Email),
            };

            var usaurio = await userManager.FindByEmailAsync(credencialesUsuario.Email);
            var claimsRoles = await userManager.GetClaimsAsync(usaurio!);

            claims.AddRange(claimsRoles);

            var llave = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["LlaveJWT"]!));
            var cred = new SigningCredentials(llave, SecurityAlgorithms.HmacSha256);

            var expiracion = DateTime.Now.AddDays(1);

            var securityToken = new JwtSecurityToken(issuer: null,
                audience: null, claims:  claims, expires:  expiracion,
                signingCredentials: cred);

            return new RespuestaAuthentication
            {
                Token = new JwtSecurityTokenHandler().WriteToken(securityToken),
                Expiration = expiracion,
            };
        }

        [HttpGet("RenovarToken")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ActionResult<RespuestaAuthentication>> Renovar()
        {
            var emailClaim = HttpContext.User.Claims.Where(x => x.Type == "email").FirstOrDefault();
            var credencialesUusario = new CredencialesUsuario()
            {
                Email = emailClaim!.Value
            };

            return await ConstruirToken(credencialesUusario);
        }

        [HttpPost("registrar")]
        public async Task<ActionResult<RespuestaAuthentication>> Registrar(CredencialesUsuario credencialesUsuario)
        {
            var usuario = new IdentityUser
            {
                UserName = credencialesUsuario.Email,
                Email = credencialesUsuario?.Email,
            };

            var resuktado = await userManager.CreateAsync(usuario, credencialesUsuario!.Password);
            if(resuktado.Succeeded)
                return await ConstruirToken(credencialesUsuario);

            return BadRequest(resuktado.Errors);    
        }

        [HttpPost("Login")]
        public async Task<ActionResult<RespuestaAuthentication>> Login(CredencialesUsuario credencialesUsuario)
        {
            var resultado = await signInManager.PasswordSignInAsync(credencialesUsuario.Email,
                credencialesUsuario.Password, isPersistent: false, lockoutOnFailure: false);
            if (resultado.Succeeded)
            {
                return await ConstruirToken(credencialesUsuario);
            }
            else
            {
                var error = new MensajeError()
                {
                    Error = "Login incorrecto"
                };

                return BadRequest(error);
            }
        }
    }
}
