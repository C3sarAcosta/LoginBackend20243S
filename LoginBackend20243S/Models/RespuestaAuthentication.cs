namespace LoginBackend20243S.Models
{
    public class RespuestaAuthentication
    {
        public string Token { get; set; }
        public DateTime Expiration { get; set; }
    }
}
