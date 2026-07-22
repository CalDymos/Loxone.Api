using Newtonsoft.Json;

namespace Loxone.Api.Data
{
    public class GetPublicKeyResponse : LoxoneApiResponseLL
    {
        [JsonProperty("Value")]
        public string PublicKey { get; set; }
    }
}
