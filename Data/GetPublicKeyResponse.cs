using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Text;

namespace Loxone.Api.Data
{
    public class GetPublicKeyResponse : LoxoneApiResponseLL
    {
        [JsonProperty("Value")]
        public string PublicKey { get; set; }
    }
}
