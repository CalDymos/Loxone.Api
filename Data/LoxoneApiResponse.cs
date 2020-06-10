using Newtonsoft.Json;

namespace Loxone.Api.Data
{
    public class LoxoneApiResponse<T> where T : LoxoneApiResponseLL
    {
        [JsonProperty("LL")]
        public T Data { get; set; }
    }
}
