using System;
using System.Collections.Generic;
using System.Text;

namespace Loxone.Api.Data
{
    public class GetKeyValueLL
    {
        public string Key { get; set; }
        public string Salt { get; set; }
    }

    public class GetKeyResponseLL : LoxoneApiResponseLL
    {
        public GetKeyValueLL Value { get; set; }
    }
}
